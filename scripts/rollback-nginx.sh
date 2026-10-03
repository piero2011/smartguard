#!/usr/bin/env bash
# =============================================================================
# SmartGuard — rollback de Nginx (punto 48)
# =============================================================================
# Uso:
#   sudo rollback-nginx.sh --list
#   sudo rollback-nginx.sh --disable [--dry-run]
#        Neutraliza SmartGuard en Nginx SIN tocar tus vhosts: los include siguen siendo válidos pero
#        no hacen nada (sin auth_request, sin límites nuevos, sin reglas nuevas). Reversible con
#        `smartguard nginx-enable`. Es la vía recomendada y la más rápida.
#   sudo rollback-nginx.sh --restore /etc/nginx/backups/nginx-XXXX.tar.gz [--dry-run]
#        Restaura /etc/nginx COMPLETO desde un backup (antes hace un backup del estado actual).
#
# ⚠ CloudPanel guarda el vhost en su base de datos. Tras --restore, pega también el vhost
#   original en CloudPanel (Sites → Vhost) o CloudPanel lo regenerará con la versión nueva.
#   El vhost original está dentro del backup: etc/nginx/sites-enabled/<dominio>.conf
# =============================================================================
set -Eeuo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SELF_DIR/lib/common.sh"
# shellcheck source=lib/nginx-gen.sh
. "$SELF_DIR/lib/nginx-gen.sh"

MODE=""; FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --list) MODE=list ;;
    --disable) MODE=disable ;;
    --restore) MODE=restore; FILE=${2:-}; shift ;;
    --dry-run) DRY_RUN=true ;;
    --yes|-y) ASSUME_YES=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "Opción desconocida: $1" ;;
  esac
  shift
done
require_root
[ -n "$MODE" ] || { sed -n '2,20p' "$0"; exit 1; }

case "$MODE" in
  list)
    ls -1t "$NGX_BACKUPS"/nginx-*.tar.gz 2>/dev/null | while read -r f; do
      printf '%s  %s\n' "$(du -h "$f" | cut -f1)" "$f"
    done
    ;;

  disable)
    confirm "¿Neutralizar SmartGuard en Nginx (tráfico directo a PHP como antes)?" || die "Cancelado."
    backup_nginx pre-disable
    [ "$DRY_RUN" != true ] && mkdir -p "$NGX_SG/disabled-originals" && cp -a "$NGX_SG"/{server,auth,auth-php,static-log}.conf "$NGX_SG/disabled-originals/" 2>/dev/null || true
    write_neutral_stubs
    if ! nginx_safe_reload; then
      warn "nginx -t falló con los archivos neutros; restaurando los anteriores."
      cp -a "$NGX_SG/disabled-originals/"*.conf "$NGX_SG/" 2>/dev/null || true
      die "Rollback no aplicado."
    fi
    ok "SmartGuard neutralizado en Nginx. Reactivar: sudo smartguard nginx-enable"
    ;;

  restore)
    [ -f "$FILE" ] || die "Backup no encontrado: $FILE"
    case "$FILE" in "$NGX_BACKUPS"/*.tar.gz) ;; *) die "Solo se aceptan backups de $NGX_BACKUPS" ;; esac
    TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
    tar xzf "$FILE" -C "$TMP"
    [ -f "$TMP/nginx/nginx.conf" ] || die "El backup no contiene nginx/nginx.conf"
    log "Diferencias entre /etc/nginx actual y el backup:"
    diff -rq --exclude=backups /etc/nginx "$TMP/nginx" | head -n 50 || true
    confirm "¿Restaurar /etc/nginx desde $FILE?" || die "Cancelado."
    backup_nginx pre-restore
    PRE="$BACKUP_PATH"
    if [ "$DRY_RUN" = true ]; then echo "[dry-run] rsync -a --delete --exclude=backups $TMP/nginx/ /etc/nginx/"; exit 0; fi
    if command -v rsync >/dev/null; then
      rsync -a --delete --exclude=backups "$TMP/nginx/" /etc/nginx/
    else
      find /etc/nginx -mindepth 1 -maxdepth 1 ! -name backups -exec rm -rf {} +
      cp -a "$TMP/nginx/." /etc/nginx/
    fi
    if ! nginx_safe_reload; then
      warn "El backup restaurado no pasa nginx -t. Volviendo al estado previo ($PRE)…"
      TMP2=$(mktemp -d); tar xzf "$PRE" -C "$TMP2"
      find /etc/nginx -mindepth 1 -maxdepth 1 ! -name backups -exec rm -rf {} +
      cp -a "$TMP2/nginx/." /etc/nginx/; rm -rf "$TMP2"
      nginx -t && systemctl reload nginx
      die "Restauración revertida."
    fi
    ok "Nginx restaurado desde $FILE (estado previo guardado en $PRE)."
    warn "Recuerda pegar el vhost original en CloudPanel para que no se regenere con la versión nueva."
    ;;
esac
