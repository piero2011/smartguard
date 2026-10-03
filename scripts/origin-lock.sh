#!/usr/bin/env bash
# =============================================================================
# SmartGuard — bloqueo del origen: 80/443 solo desde Cloudflare + IPs de confianza (punto 43)
# =============================================================================
# Uso:
#   sudo origin-lock.sh check                 # NO cambia nada: comprueba si es seguro activarlo
#   sudo origin-lock.sh enable [--dry-run] [--force]
#   sudo origin-lock.sh disable
#
# NO activar hasta que "check" pase: si algún dominio está en "DNS only" (nube gris), o un servicio
# externo (webhook de pasarela, API) conecta directo a la IP del VPS, quedaría cortado.
# Let's Encrypt HTTP-01 sigue funcionando porque llega a través del proxy de Cloudflare.
# Tu IP de administración (ADMIN_ALLOWLIST) mantiene acceso directo.
# =============================================================================
set -Eeuo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SELF_DIR/lib/common.sh"

CMD=${1:-help}; shift || true
FORCE=false
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=true ;;
    --force) FORCE=true ;;
    *) die "Opción desconocida: $a" ;;
  esac
done
require_root
FLAG="$SG_ETC/nftables/origin-lock.enabled"
NODE=$(node_bin)

# ¿IP en rangos Cloudflare? (usa ipaddr.js de SmartGuard: IPv4 e IPv6 correctos)
in_cloudflare() {
  "$NODE" -e '
    const ipaddr = require("/opt/smartguard/node_modules/ipaddr.js");
    const fs = require("fs");
    const ranges = fs.readFileSync("/etc/smartguard/cloudflare-ips.txt","utf8").split("\n").filter(l=>l && !l.startsWith("#")).map(l=>ipaddr.parseCIDR(l.trim()));
    let a = ipaddr.parse(process.argv[1]); if (a.kind()==="ipv6" && a.isIPv4MappedAddress()) a = a.toIPv4Address();
    process.exit(ranges.some(r => r[0].kind()===a.kind() && a.match(r)) ? 0 : 1);
  ' "$1"
}

check() {
  local fail=0 names name ips ip
  [ -r "$SG_ETC/cloudflare-ips.txt" ] || die "Falta $SG_ETC/cloudflare-ips.txt (ejecuta update-cloudflare-ips.sh)"
  nft list table inet smartguard >/dev/null 2>&1 || { warn "La tabla inet smartguard no está cargada (instala con --enable-nftables)"; fail=1; }

  log "1) Dominios servidos por Nginx y a dónde resuelven:"
  names=$(nginx -T 2>/dev/null | grep -E '^\s*server_name\s' | sed -E 's/^\s*server_name\s+//; s/;.*$//' | tr ' ' '\n' \
          | grep -vE '^(_|localhost|\*.*|~.*|[0-9.]+|)$' | sort -u)
  for name in $names; do
    ips=$(getent ahosts "$name" | awk '{print $1}' | sort -u || true)
    if [ -z "$ips" ]; then warn "   $name: no resuelve (¿dominio sin uso?)"; continue; fi
    for ip in $ips; do
      if in_cloudflare "$ip"; then printf '   %-45s %-40s Cloudflare ✔\n' "$name" "$ip"
      else printf '   %s%-45s %-40s NO es Cloudflare ✘ (DNS only / directo)%s\n' "$C_RED" "$name" "$ip" "$C_RST"; fail=1; fi
    done
  done

  log "2) IPs de confianza (acceso directo que se conservará):"
  local n; n=$(allowlist_entries | wc -l)
  if [ "$n" -eq 0 ]; then warn "   ADMIN_ALLOWLIST/SERVICE_ALLOWLIST/TRUSTED_NETWORKS vacías: perderías el acceso HTTP directo de emergencia."; fail=1
  else allowlist_entries | sed 's/^/   /'; fi

  log "3) Conexiones DIRECTAS recientes (no Cloudflare) según el log de SmartGuard (quedarían bloqueadas):"
  if [ -r "$SG_LOGDIR/access.json" ]; then
    grep -h '"cf":0' "$SG_LOGDIR"/access.json* 2>/dev/null | grep -oE '"tcp":"[^"]+"' | sort | uniq -c | sort -rn | head -n 15 | sed 's/^/   /' || true
  fi
  log "   Conexiones TCP establecidas ahora mismo a 80/443 desde fuera de Cloudflare:"
  ss -Htn state established '( sport = :443 or sport = :80 )' 2>/dev/null | awk '{print $4}' | sed -E 's/:[0-9]+$//; s/^\[|\]$//g' \
    | sort -u | head -n 200 | while read -r ip; do in_cloudflare "$ip" || echo "   $ip"; done | head -n 20

  echo
  if [ "$fail" -eq 0 ]; then ok "check superado. Revisa manualmente la lista 3 (webhooks/APIs directas) antes de 'enable'."
  else warn "check NO superado: no actives origin-lock todavía."; fi
  return "$fail"
}

case "$CMD" in
  check) check ;;
  enable)
    if ! check && [ "$FORCE" != true ]; then die "No se activa (usa --force solo si entiendes el riesgo)."; fi
    run "$SG_FWSYNC"
    if [ "$DRY_RUN" = true ]; then nft -c -f "$SG_ETC/nftables/origin-lock.nft" && ok "[dry-run] origin-lock.nft válido; no aplicado"; exit 0; fi
    nft -f "$SG_ETC/nftables/origin-lock.nft"
    touch "$FLAG"
    ok "origin-lock ACTIVO: 80/443 solo desde Cloudflare + IPs de confianza. Desactivar: origin-lock.sh disable"
    ;;
  disable)
    run nft flush chain inet smartguard origin_lock
    run rm -f "$FLAG"
    ok "origin-lock desactivado"
    ;;
  *) sed -n '2,15p' "$0" ;;
esac
