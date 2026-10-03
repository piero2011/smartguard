#!/usr/bin/env bash
# =============================================================================
# SmartGuard — desinstalación sin destruir la configuración original (punto 86)
# =============================================================================
# Uso:  sudo /opt/smartguard/scripts/uninstall.sh [--dry-run] [--yes] [--purge]
#
# Por defecto:
#   - Backup de /etc/nginx; neutraliza los snippets (tus vhosts siguen siendo válidos);
#     elimina el archivo http global (conf.d/smartguard.conf o sites-enabled/00-smartguard.conf)
#     y con él el realip de Cloudflare instalado por SmartGuard.
#   - Detiene y elimina servicios systemd, la tabla nftables, la app (/opt/smartguard) y el CLI.
#   - CONSERVA: /etc/smartguard (config/secretos), /etc/nginx/smartguard (stubs neutros),
#     /etc/nginx/backups, datos en Redis, log JSON.
# --purge (solo cuando ya quitaste los include de SmartGuard de TODOS tus vhosts en CloudPanel):
#   elimina además /etc/nginx/smartguard, /etc/smartguard, /var/lib/smartguard, el log JSON,
#   las claves smartguard:* de Redis (SCAN + UNLINK, nunca KEYS) y el usuario smartguard.
# =============================================================================
set -Eeuo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Copia local de las librerías: este script borra /opt/smartguard
LIBTMP=$(mktemp -d); cp -a "$SELF_DIR/lib/." "$LIBTMP/"; trap 'rm -rf "$LIBTMP"' EXIT
# shellcheck source=lib/common.sh
. "$LIBTMP/common.sh"
# shellcheck source=lib/nginx-gen.sh
. "$LIBTMP/nginx-gen.sh"

PURGE=false
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=true ;;
    --yes|-y) ASSUME_YES=true ;;
    --purge) PURGE=true ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "Opción desconocida: $a" ;;
  esac
done
require_root

resolve_http_conf || true
REFS=$(grep -rlE '/etc/nginx/smartguard/' /etc/nginx/sites-enabled /etc/nginx/sites-available /etc/nginx/conf.d 2>/dev/null \
  | grep -vE '/(conf\.d/smartguard|sites-enabled/00-smartguard)\.conf$' || true)
if [ "$PURGE" = true ] && [ -n "$REFS" ]; then
  warn "Estos archivos aún incluyen /etc/nginx/smartguard/ (quita esos include en CloudPanel primero):"
  echo "$REFS" | sed 's/^/    /'
  die "--purge cancelado para no romper Nginx."
fi

confirm "¿Desinstalar SmartGuard$([ "$PURGE" = true ] && echo ' (PURGE)')?" || die "Cancelado."
backup_nginx pre-uninstall

# 1) Nginx: neutralizar y quitar el contexto http
if [ -d "$NGX_SG" ]; then write_neutral_stubs; fi
[ -n "$NGX_CONFD" ] && run rm -f "$NGX_CONFD"
if ! nginx_safe_reload; then
  warn "nginx -t falla sin $NGX_CONFD (¿algún vhost usa variables sg_ directamente?). Restaurándolo."
  tar xzf "$BACKUP_PATH" -C /etc "${NGX_CONFD#/etc/}" 2>/dev/null || true
  nginx_safe_reload || true
  die "Desinstalación detenida en el paso Nginx. Backup: $BACKUP_PATH"
fi

# 2) Servicios
for u in smartguard.service smartguard-nft.service smartguard-cf-ips.timer smartguard-cf-ips.service; do
  run systemctl disable --now "$u" 2>/dev/null || true
done
run rm -f /etc/systemd/system/smartguard.service /etc/systemd/system/smartguard-nft.service \
          /etc/systemd/system/smartguard-cf-ips.service /etc/systemd/system/smartguard-cf-ips.timer
run rm -rf /etc/systemd/system/smartguard.service.d
run systemctl daemon-reload

# 3) nftables
if command -v nft >/dev/null && nft list table inet smartguard >/dev/null 2>&1; then
  run nft delete table inet smartguard
fi

# 4) App, CLI, logrotate
run rm -rf "$SG_OPT" "$SG_OPT.prev" "$SG_OPT.new"
run rm -f "$SG_CLI" "$SG_FWSYNC" /etc/logrotate.d/smartguard-nginx

# 5) Purge
if [ "$PURGE" = true ]; then
  PREFIX=$(env_get REDIS_PREFIX); PREFIX=${PREFIX:-smartguard:}
  RH=$(env_get REDIS_HOST); RP=$(env_get REDIS_PORT); RDB=$(env_get REDIS_DB); RPW=$(env_get REDIS_PASSWORD)
  if command -v redis-cli >/dev/null && [[ "$PREFIX" =~ ^[a-z0-9_-]+:$ ]]; then
    log "Borrando claves ${PREFIX}* de Redis (SCAN)…"
    if [ "$DRY_RUN" != true ]; then
      rc() { if [ -n "$RPW" ]; then REDISCLI_AUTH="$RPW" redis-cli -h "${RH:-127.0.0.1}" -p "${RP:-6379}" -n "${RDB:-0}" "$@"; else redis-cli -h "${RH:-127.0.0.1}" -p "${RP:-6379}" -n "${RDB:-0}" "$@"; fi; }
      batch=()
      while read -r k; do
        [ -n "$k" ] && batch+=("$k")
        if [ ${#batch[@]} -ge 500 ]; then rc UNLINK "${batch[@]}" >/dev/null; batch=(); fi
      done < <(rc --scan --pattern "${PREFIX}*")
      [ ${#batch[@]} -gt 0 ] && rc UNLINK "${batch[@]}" >/dev/null
      ok "Claves ${PREFIX}* eliminadas de Redis"
    fi
  fi
  run rm -rf "$NGX_SG" "$SG_ETC" "$SG_VAR" "$SG_LOGDIR"
  id smartguard >/dev/null 2>&1 && run userdel smartguard
  nginx_safe_reload || true
fi

ok "SmartGuard desinstalado. Backup de Nginx: $BACKUP_PATH"
[ "$PURGE" = true ] || cat <<EOF
Quedan (a propósito):
  $NGX_SG     → archivos NEUTROS para que tus vhosts sigan siendo válidos.
  $SG_ETC     → configuración y secretos.
Para terminar: restaura tu vhost original en CloudPanel (está en el backup:
  etc/nginx/sites-enabled/<dominio>.conf) y ejecuta de nuevo con --purge.
EOF
