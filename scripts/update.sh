#!/usr/bin/env bash
# =============================================================================
# SmartGuard — actualización conservando configuración (punto 88)
# =============================================================================
# Uso:  cd smartguard-nueva-version && sudo ./scripts/update.sh [--dry-run] [--yes]
#       sudo /opt/smartguard/scripts/update.sh --revert      # vuelve a la versión anterior
#
# Conserva SIEMPRE: /etc/smartguard/smartguard.env, rules.yaml, sites.yaml, bots.yaml, rules.d/,
#   allowlists, /etc/nginx/smartguard/rate-limits.conf, mode.conf, limits-mode.conf,
#   allowlist.conf, secret.conf, cloudflare-*.conf, y el estado en Redis.
# Actualiza: /opt/smartguard (con copia en /opt/smartguard.prev), snippets Nginx de "código"
#   (maps/server/auth/auth-php/static-log/log-format/upstream) tras backup y nginx -t.
# Muestra las variables NUEVAS de .env.example que no están en tu .env (no las añade solas).
# =============================================================================
set -Eeuo pipefail
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$SRC_DIR/scripts/lib/common.sh"

REVERT=false
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=true ;;
    --yes|-y) ASSUME_YES=true ;;
    --revert) REVERT=true ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die "Opción desconocida: $a" ;;
  esac
done
require_root
[ -d "$SG_OPT" ] || die "SmartGuard no está instalado (usa install.sh)."

health() {
  local port; port=$(env_get PORT); port=${port:-3100}
  for _ in $(seq 1 15); do curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

if [ "$REVERT" = true ]; then
  [ -d "$SG_OPT.prev" ] || die "No existe $SG_OPT.prev"
  confirm "¿Volver a la versión anterior de SmartGuard?" || die "Cancelado."
  run mv "$SG_OPT" "$SG_OPT.failed.$(date +%s)"
  run mv "$SG_OPT.prev" "$SG_OPT"
  run systemctl restart smartguard
  health && ok "Versión anterior restaurada" || warn "No responde: journalctl -u smartguard -n 50"
  exit 0
fi

[ "$SRC_DIR" != "$SG_OPT" ] || die "Ejecuta update.sh desde la carpeta de la NUEVA versión, no desde $SG_OPT."
CUR=$(node -p "require('$SG_OPT/package.json').version" 2>/dev/null || echo "?")
NEW=$(node -p "require('$SRC_DIR/package.json').version")
log "Actualizar SmartGuard $CUR → $NEW"

# Variables nuevas en .env.example
MISSING=$(grep -oE '^[A-Z_]+=' "$SRC_DIR/.env.example" | while read -r k; do grep -q "^$k" "$SG_ENV" || echo "${k%=}"; done)
[ -n "$MISSING" ] && warn "Variables nuevas disponibles (se usan valores por defecto; añádelas si quieres cambiarlas): $(echo "$MISSING" | tr '\n' ' ')"
confirm "¿Continuar?" || die "Cancelado."

backup_nginx pre-update
STAGE="$SG_OPT.new"
run rm -rf "$STAGE"
run install -d -m 0755 "$STAGE"
for item in package.json package-lock.json tsconfig.json tsconfig.build.json src config scripts bin nginx nftables systemd logrotate docs README.md .env.example; do
  [ -e "$SRC_DIR/$item" ] && run cp -a "$SRC_DIR/$item" "$STAGE/"
done
if [ "$DRY_RUN" != true ]; then
  (
    cd "$STAGE"
    if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund; else npm install --ignore-scripts --no-audit --no-fund; fi
    npm run build
    npm prune --omit=dev --ignore-scripts --no-audit --no-fund
  ) || die "Falló la compilación: la versión instalada NO se ha tocado."
  install_dashboard "$SRC_DIR" "$STAGE"
  chown -R root:root "$STAGE"; chmod -R go-w "$STAGE"; chmod 0755 "$STAGE"/scripts/*.sh "$STAGE/bin/smartguard"
fi

# Validar las reglas del usuario con el código nuevo ANTES de cambiar nada
if [ "$DRY_RUN" != true ]; then
  (cd "$STAGE" && CONFIG_DIR="$SG_ETC" NODE_ENV=test REDIS_ENABLED=false node -e '
    const { ConfigService } = require("./dist/config/config.service");
    const { RulesService } = require("./dist/rules/rules.service");
    const { loadEnv } = require("./dist/config/env");
    (async () => { const c = new ConfigService(loadEnv()); await c.loadFiles(); console.log(JSON.stringify(new RulesService(c).compile())); })()
      .catch(e => { console.error(e.message); process.exit(1); });') \
    || die "Tus reglas/sitios en $SG_ETC no son válidos con la nueva versión. Nada cambiado."
  ok "Configuración de $SG_ETC validada con la nueva versión"
fi

# Snippets de código Nginx (los editables/generados se conservan)
for f in maps.conf server.conf auth.conf auth-php.conf static-log.conf log-format.conf upstream.conf; do
  [ -f "$NGX_SG/$f" ] && run cp -a "$NGX_SG/$f" "$NGX_SG/$f.pre-update"
  if grep -q 'DESACTIVADO' "$NGX_SG/$f" 2>/dev/null; then
    warn "$f está neutralizado (rollback --disable); se actualiza la copia en disabled-originals/"
    run install -m 0644 "$SRC_DIR/nginx/smartguard/$f" "$NGX_SG/disabled-originals/$f"
    continue
  fi
  run install -o root -g root -m 0644 "$SRC_DIR/nginx/smartguard/$f" "$NGX_SG/$f"
done
if ! nginx_safe_reload; then
  warn "Restaurando snippets anteriores…"
  for f in "$NGX_SG"/*.pre-update; do [ -f "$f" ] && mv -f "$f" "${f%.pre-update}"; done
  nginx -t >/dev/null 2>&1 && systemctl reload nginx
  run rm -rf "$STAGE"
  die "Nginx rechazó los snippets nuevos. Nada cambiado. Backup: $BACKUP_PATH"
fi
run rm -f "$NGX_SG"/*.pre-update

# Cambiar aplicación
if [ "$DRY_RUN" != true ]; then
  rm -rf "$SG_OPT.prev"; mv "$SG_OPT" "$SG_OPT.prev"; mv "$STAGE" "$SG_OPT"
fi
run install -o root -g root -m 0755 "$SRC_DIR/bin/smartguard" "$SG_CLI"
[ -f "$SG_FWSYNC" ] && run install -o root -g root -m 0750 "$SRC_DIR/scripts/smartguard-fw-sync" "$SG_FWSYNC"
NODE_BIN=$(node_bin)
sed "s|^ExecStart=/usr/bin/node |ExecStart=$NODE_BIN |" "$SRC_DIR/systemd/smartguard.service" | write_file /etc/systemd/system/smartguard.service 0644
run systemctl daemon-reload
run systemctl restart smartguard

if [ "$DRY_RUN" = true ] || health; then
  ok "SmartGuard $NEW en marcha. Versión anterior en $SG_OPT.prev (revertir: update.sh --revert)"
else
  warn "La nueva versión no responde; revirtiendo…"
  mv "$SG_OPT" "$SG_OPT.failed.$(date +%s)"; mv "$SG_OPT.prev" "$SG_OPT"
  systemctl restart smartguard
  die "Actualización revertida. Revisa: journalctl -u smartguard -n 80 --no-pager"
fi
