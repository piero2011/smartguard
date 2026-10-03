#!/usr/bin/env bash
# =============================================================================
# SmartGuard — actualización SEGURA y ATÓMICA de los rangos de Cloudflare (puntos 43, 44)
# =============================================================================
# Uso: sudo update-cloudflare-ips.sh [--dry-run] [--force] [--no-reload]
#
# Genera a partir de https://www.cloudflare.com/ips-v4 y /ips-v6:
#   /etc/nginx/smartguard/cloudflare-realip.conf  (set_real_ip_from + real_ip_header CF-Connecting-IP)
#   /etc/nginx/smartguard/cloudflare-geo.conf     ($sg_tcp_from_cloudflare)
#   /etc/smartguard/cloudflare-ips.txt            (SmartGuard: nunca banear Cloudflare)
#   sets nftables cloudflare_v4/v6                (si la tabla inet smartguard existe)
#
# Garantías:
#   - Descarga solo por HTTPS (TLS ≥ 1.2), con timeout.
#   - Cada línea se valida como CIDR estricto; cantidades mínimas/máximas.
#   - Si la lista nueva elimina > 50% de la actual, se aborta (salvo --force).
#   - NUNCA se vacía la lista actual antes de tener una nueva válida.
#   - Escritura atómica (tmp + mv); nginx -t antes de recargar; si falla se restaura.
#   - nftables: flush + add en UNA transacción (nft -f), sin ventana vacía.
# =============================================================================
set -Eeuo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SELF_DIR/lib/common.sh"

FORCE=false
RELOAD=true
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=true ;;
    --force) FORCE=true ;;
    --no-reload) RELOAD=false ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) die "Opción desconocida: $a" ;;
  esac
done
require_root

TXT="$SG_ETC/cloudflare-ips.txt"
REALIP="$NGX_SG/cloudflare-realip.conf"
GEO="$NGX_SG/cloudflare-geo.conf"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fetch() {
  curl --fail --silent --show-error --location --max-time 20 --proto '=https' --tlsv1.2 \
       --retry 2 --retry-delay 3 -o "$2" "$1"
}
log "Descargando rangos de Cloudflare…"
fetch https://www.cloudflare.com/ips-v4 "$WORK/v4.raw" || die "No se pudo descargar ips-v4 (se mantiene la lista actual)."
fetch https://www.cloudflare.com/ips-v6 "$WORK/v6.raw" || die "No se pudo descargar ips-v6 (se mantiene la lista actual)."

: >"$WORK/v4"; : >"$WORK/v6"
while read -r l; do
  l=${l%%$'\r'}; [ -z "$l" ] && continue
  is_cidr_v4 "$l" && [[ "$l" == */* ]] || die "Línea IPv4 inválida en la respuesta de Cloudflare: '$l' (abortado, nada cambiado)"
  echo "$l" >>"$WORK/v4"
done <"$WORK/v4.raw"
while read -r l; do
  l=${l%%$'\r'}; [ -z "$l" ] && continue
  is_cidr_v6 "$l" && [[ "$l" == */* ]] || die "Línea IPv6 inválida en la respuesta de Cloudflare: '$l' (abortado, nada cambiado)"
  echo "$l" | tr 'A-F' 'a-f' >>"$WORK/v6"
done <"$WORK/v6.raw"

N4=$(wc -l <"$WORK/v4"); N6=$(wc -l <"$WORK/v6")
{ [ "$N4" -ge 10 ] && [ "$N4" -le 200 ] && [ "$N6" -ge 5 ] && [ "$N6" -le 200 ]; } \
  || die "Cantidad sospechosa de rangos (v4=$N4, v6=$N6). Abortado, nada cambiado."
sort -u "$WORK/v4" "$WORK/v6" >"$WORK/all"

if [ -f "$TXT" ]; then
  grep -vE '^\s*(#|$)' "$TXT" | sort -u >"$WORK/old" || true
  OLD=$(wc -l <"$WORK/old")
  REMOVED=$(comm -23 "$WORK/old" "$WORK/all" | wc -l)
  ADDED=$(comm -13 "$WORK/old" "$WORK/all" | wc -l)
  log "Cambios: +$ADDED / -$REMOVED (actual: $OLD, nueva: $((N4 + N6)))"
  if [ "$OLD" -gt 0 ] && [ $((REMOVED * 2)) -gt "$OLD" ] && [ "$FORCE" != true ]; then
    die "La nueva lista elimina más del 50% de los rangos actuales. Revisa manualmente o usa --force."
  fi
  if [ "$REMOVED" -eq 0 ] && [ "$ADDED" -eq 0 ]; then
    ok "Sin cambios en los rangos de Cloudflare."
    exit 0
  fi
fi

STAMP="# GENERADO por update-cloudflare-ips.sh el $(date -Is). No editar."
{
  echo "$STAMP"; echo "# Fuente: https://www.cloudflare.com/ips-v4 y ips-v6"
  cat "$WORK/all"
} >"$WORK/cloudflare-ips.txt"
{
  echo "$STAMP"
  echo "# Solo si la IP TCP pertenece a Cloudflare se acepta CF-Connecting-IP como IP real."
  while read -r c; do echo "set_real_ip_from $c;"; done <"$WORK/all"
  echo "real_ip_header CF-Connecting-IP;"
  echo "real_ip_recursive off;"
} >"$WORK/realip.conf"
{
  echo "$STAMP"
  echo "geo \$realip_remote_addr \$sg_tcp_from_cloudflare {"
  echo "    default 0;"
  while read -r c; do echo "    $c 1;"; done <"$WORK/all"
  echo "}"
} >"$WORK/geo.conf"
{
  echo "flush set inet smartguard cloudflare_v4"
  echo "flush set inet smartguard cloudflare_v6"
  echo "add element inet smartguard cloudflare_v4 { $(paste -sd, "$WORK/v4") }"
  echo "add element inet smartguard cloudflare_v6 { $(paste -sd, "$WORK/v6") }"
} >"$WORK/cf.nft"

if [ "$DRY_RUN" = true ]; then
  log "[dry-run] Se escribirían $TXT, $REALIP, $GEO y los sets nftables:"
  sed 's/^/    /' "$WORK/cf.nft"
  [ -f "$REALIP" ] && diff -u "$REALIP" "$WORK/realip.conf" | head -n 60 || true
  exit 0
fi

# Instalación atómica con respaldo para restaurar si nginx -t falla
install -d -m 0755 "$NGX_SG"
for f in "$REALIP" "$GEO"; do [ -f "$f" ] && cp -a "$f" "$f.bak"; done
install -o root -g smartguard -m 0640 "$WORK/cloudflare-ips.txt" "$TXT.tmp" && mv -f "$TXT.tmp" "$TXT"
install -o root -g root -m 0644 "$WORK/realip.conf" "$REALIP.tmp" && mv -f "$REALIP.tmp" "$REALIP"
install -o root -g root -m 0644 "$WORK/geo.conf" "$GEO.tmp" && mv -f "$GEO.tmp" "$GEO"

if ! nginx -t >/dev/null 2>&1; then
  warn "nginx -t falló con los nuevos rangos: restaurando los anteriores."
  for f in "$REALIP" "$GEO"; do [ -f "$f.bak" ] && mv -f "$f.bak" "$f"; done
  die "Rangos NO aplicados en Nginx."
fi
rm -f "$REALIP.bak" "$GEO.bak"
[ "$RELOAD" = true ] && systemctl reload nginx && ok "Nginx recargado con los nuevos rangos"

if command -v nft >/dev/null && nft list table inet smartguard >/dev/null 2>&1; then
  if nft -c -f "$WORK/cf.nft" && nft -f "$WORK/cf.nft"; then ok "Sets nftables cloudflare_v4/v6 actualizados"; else warn "No se pudieron actualizar los sets nftables"; fi
fi
ok "Rangos de Cloudflare actualizados ($N4 IPv4, $N6 IPv6). SmartGuard los relee en ≤ 1 h."
