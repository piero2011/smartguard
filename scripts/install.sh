#!/usr/bin/env bash
# =============================================================================
# SmartGuard — instalador seguro para Debian 13 (punto 85)
# =============================================================================
# Uso:  sudo ./scripts/install.sh [--dry-run] [--yes] [--enable-nftables] [--skip-realip]
#
# Qué hace (y qué NO hace):
#   ✔ Comprueba Node ≥ 22, Nginx (auth_request + realip), Redis, dónde cargar el contexto http
#   ✔ Backup COMPLETO de /etc/nginx antes de tocar nada
#   ✔ Crea usuario de sistema "smartguard" (sin shell, sin home real)
#   ✔ Instala la app en /opt/smartguard, config en /etc/smartguard (0640 root:smartguard)
#   ✔ Instala snippets en /etc/nginx/smartguard + archivo http global:
#       /etc/nginx/conf.d/smartguard.conf si nginx.conf incluye conf.d, o
#       /etc/nginx/sites-enabled/00-smartguard.conf (CloudPanel: solo incluye sites-enabled/*.conf)
#     (solo definen variables/zonas: NO cambian el tráfico hasta que el vhost los incluya)
#   ✔ AUDIT_MODE=true y reglas Nginx nuevas en AUDIT (dry-run): NO bloquea nada nuevo
#   ✔ Servicio systemd sin root
#   ✘ NO modifica tus vhosts (se editan en CloudPanel; ver docs/02-PROCEDIMIENTOS.md 13.5)
#   ✘ NO activa nftables salvo --enable-nftables (y aun así sin origin-lock)
#   ✘ NO activa Cloudflare API
# =============================================================================
set -Eeuo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$SRC_DIR/scripts/lib/common.sh"
# shellcheck source=lib/nginx-gen.sh
. "$SRC_DIR/scripts/lib/nginx-gen.sh"

ENABLE_NFT=false
SKIP_REALIP=false
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=true ;;
    --yes|-y) ASSUME_YES=true ;;
    --enable-nftables) ENABLE_NFT=true ;;
    --skip-realip) SKIP_REALIP=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "Opción desconocida: $a" ;;
  esac
done

require_root
trap 'warn "La instalación se interrumpió en la línea $LINENO. Backup: ${BACKUP_PATH:-no creado}"' ERR

# -----------------------------------------------------------------------------
# 1. Comprobaciones previas
# -----------------------------------------------------------------------------
log "Comprobaciones previas…"
. /etc/os-release 2>/dev/null || true
if [ "${ID:-}" != debian ] || [ "${VERSION_ID:-}" != 13 ]; then
  warn "Probado en Debian 13; detectado: ${PRETTY_NAME:-desconocido}. Continúa bajo tu responsabilidad."
fi

for bin in curl tar openssl nginx systemctl; do
  command -v "$bin" >/dev/null || die "Falta '$bin'. Instálalo: apt-get install -y $bin"
done

NODE_BIN=$(node_bin)
[ -n "$NODE_BIN" ] || die "Node.js no encontrado. Instala Node ≥ 22 del sistema (NodeSource; el nodejs de apt en Debian 13 es 20.x y no sirve)."
case "$NODE_BIN" in
  /home/*|/root/*) die "Node está en $NODE_BIN (nvm/usuario). systemd con ProtectHome no puede usarlo. Instala Node del sistema (apt/NodeSource) en /usr/bin." ;;
esac
NODE_VER=$("$NODE_BIN" -p 'process.versions.node')
"$NODE_BIN" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' \
  || die "Node $NODE_VER es demasiado antiguo (mínimo 22: lo exige la librería de métricas @prometheus-io/client). Instálalo desde NodeSource."
command -v npm >/dev/null || die "Falta npm (apt-get install -y npm)."
ok "Node $NODE_VER en $NODE_BIN"

NGX_V=$(nginx -v 2>&1 | sed -E 's/.*nginx\/([0-9.]+).*/\1/')
NGX_FLAGS=$(nginx -V 2>&1)
grep -q -- '--with-http_auth_request_module' <<<"$NGX_FLAGS" || die "Nginx sin http_auth_request_module (necesario para SmartGuard en línea)."
grep -q -- '--with-http_realip_module' <<<"$NGX_FLAGS" || die "Nginx sin http_realip_module (necesario para la IP real con Cloudflare)."
"$NODE_BIN" -e "const v='$NGX_V'.split('.').map(Number);process.exit(v[0]>1||(v[0]===1&&v[1]>=18)?0:1)" \
  || die "Nginx $NGX_V demasiado antiguo (mínimo 1.18: limit_req_dry_run, \$limit_req_status)."
ok "Nginx $NGX_V con auth_request y realip"

nginx -t >/dev/null 2>&1 || die "La configuración ACTUAL de Nginx ya falla 'nginx -t'. Corrígela antes de instalar."
NGX_T=$(nginx -T 2>/dev/null)
resolve_http_conf || die "nginx.conf no incluye ni /etc/nginx/conf.d/*.conf ni /etc/nginx/sites-enabled/*.conf dentro de http {}."
case "$NGX_CONFD" in
  */sites-enabled/*) warn "nginx.conf no incluye conf.d: el contexto http de SmartGuard irá en $NGX_CONFD (se carga antes que los vhosts; CloudPanel no lo gestiona)." ;;
esac
ok "Contexto http de SmartGuard: $NGX_CONFD"

REALIP_EXISTS=false
# real_ip definido FUERA de /etc/nginx/smartguard/ (nginx -T marca cada archivo con
# "# configuration file <ruta>:"; así una reinstalación no cuenta el realip propio).
# Sin "grep -q" ni "head" leyendo de una tubería: con un nginx -T grande cortan la lectura, el
# productor recibe SIGPIPE y pipefail lo convierte en un falso "no existe".
REALIP_FOUND=$(awk '
  /^# configuration file / { f = $4; sub(/:$/, "", f); next }
  f !~ /^\/etc\/nginx\/smartguard\// && /^[[:space:]]*(real_ip_header|set_real_ip_from|real_ip_recursive)[[:space:]]/ { print f ": " $0 }
' <<<"$NGX_T")
if [ -n "$REALIP_FOUND" ]; then
  REALIP_EXISTS=true
  warn "Ya existe configuración real_ip en Nginx: NO se activará cloudflare-realip.conf (evita 'duplicate')."
  warn "Verifica que sea CF-Connecting-IP con las redes oficiales de Cloudflare:"
  sed -n -e 's/^/    /' -e '1,8p' <<<"$REALIP_FOUND"
fi
[ "$SKIP_REALIP" = true ] && REALIP_EXISTS=true

REDIS_HOST=$(env_get REDIS_HOST); REDIS_HOST=${REDIS_HOST:-127.0.0.1}
REDIS_PORT=$(env_get REDIS_PORT); REDIS_PORT=${REDIS_PORT:-6379}
if command -v redis-cli >/dev/null && redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping 2>/dev/null | grep -q PONG; then
  ok "Redis responde en $REDIS_HOST:$REDIS_PORT"
else
  warn "Redis no responde sin contraseña en $REDIS_HOST:$REDIS_PORT (o no hay redis-cli). SmartGuard funcionará en modo degradado (memoria) hasta configurar REDIS_* en $SG_ENV."
fi

if [ "$ENABLE_NFT" = true ]; then
  command -v nft >/dev/null || die "--enable-nftables requiere nftables (apt-get install -y nftables)."
fi

# -----------------------------------------------------------------------------
# 2. Plan
# -----------------------------------------------------------------------------
cat <<EOF

${C_BLD}SmartGuard va a realizar estos cambios:${C_RST}
  • Backup completo:        $NGX_BACKUPS/nginx-<fecha>-pre-install.tar.gz
  • Usuario de sistema:     smartguard (grupo adm para leer el log JSON)
  • Aplicación:             $SG_OPT          (root:root, solo lectura para el servicio)
  • Configuración:          $SG_ETC          (.env con secretos generados, AUDIT_MODE=true)
  • Estado:                 $SG_VAR
  • Log JSON de Nginx:      $SG_LOGDIR
  • Snippets Nginx:         $NGX_SG/*
  • Contexto http:          $NGX_CONFD  (realip Cloudflare: $([ "$REALIP_EXISTS" = true ] && echo 'NO, ya existe' || echo 'SÍ'))
  • systemd:                smartguard.service (+ timer semanal de rangos Cloudflare)
  • logrotate:              /etc/logrotate.d/smartguard-nginx
  • CLI:                    $SG_CLI
  • nftables:               $([ "$ENABLE_NFT" = true ] && echo 'SÍ (tabla inet smartguard, sin origin-lock)' || echo 'NO (archivos copiados, desactivado)')

  ${C_BLD}NO se modifica ningún vhost.${C_RST} Todo queda en AUDIT: nada nuevo se bloquea.
EOF
[ "$DRY_RUN" = true ] && warn "Modo --dry-run: no se escribirá nada."
confirm "¿Continuar?" || die "Cancelado."

# -----------------------------------------------------------------------------
# 3. Backup
# -----------------------------------------------------------------------------
backup_nginx pre-install

# -----------------------------------------------------------------------------
# 4. Usuario y directorios
# -----------------------------------------------------------------------------
if ! id smartguard >/dev/null 2>&1; then
  run useradd --system --user-group --home-dir "$SG_VAR" --no-create-home --shell /usr/sbin/nologin smartguard
fi
run usermod -aG adm smartguard
run install -d -o root -g smartguard -m 0750 "$SG_ETC" "$SG_ETC/rules.d" "$SG_ETC/nftables"
run install -d -o smartguard -g smartguard -m 0750 "$SG_VAR"
run install -d -o root -g adm -m 0750 "$SG_LOGDIR"
run install -d -o root -g root -m 0755 "$NGX_SG"

# -----------------------------------------------------------------------------
# 5. Compilar e instalar la aplicación (build aislado, --ignore-scripts)
# -----------------------------------------------------------------------------
STAGE="$SG_OPT.new"
log "Compilando SmartGuard en $STAGE…"
run rm -rf "$STAGE"
run install -d -m 0755 "$STAGE"
for item in package.json package-lock.json tsconfig.json tsconfig.build.json src config scripts bin nginx nftables systemd logrotate docs README.md .env.example; do
  [ -e "$SRC_DIR/$item" ] && run cp -a "$SRC_DIR/$item" "$STAGE/"
done
# Commit instalado: "smartguard update" lo compara con GitHub para saber si hay cambios
if [ "$DRY_RUN" != true ]; then
  git -C "$SRC_DIR" rev-parse HEAD >"$STAGE/COMMIT" 2>/dev/null || rm -f "$STAGE/COMMIT"
fi
if [ "$DRY_RUN" != true ]; then
  (
    cd "$STAGE"
    if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund; else npm install --ignore-scripts --no-audit --no-fund; fi
    npm run build
    npm prune --omit=dev --ignore-scripts --no-audit --no-fund
  ) || die "Falló la compilación (no se ha tocado la instalación existente)."
  install_dashboard "$SRC_DIR" "$STAGE"
  chown -R root:root "$STAGE"
  chmod -R go-w "$STAGE"
  chmod 0755 "$STAGE"/scripts/*.sh "$STAGE/bin/smartguard"
  if [ -d "$SG_OPT" ]; then rm -rf "$SG_OPT.prev"; mv "$SG_OPT" "$SG_OPT.prev"; fi
  mv "$STAGE" "$SG_OPT"
fi
ok "Aplicación instalada en $SG_OPT"

# -----------------------------------------------------------------------------
# 6. Configuración (nunca sobrescribe la existente)
# -----------------------------------------------------------------------------
if [ ! -f "$SG_ENV" ]; then
  ADMIN_TOKEN=$(openssl rand -hex 32)
  SHARED=$(openssl rand -hex 24)
  sed -e "s|^ADMIN_TOKEN=.*|ADMIN_TOKEN=$ADMIN_TOKEN|" \
      -e "s|^DECISION_SHARED_SECRET=.*|DECISION_SHARED_SECRET=$SHARED|" \
      -e "s|^AUDIT_MODE=.*|AUDIT_MODE=true|" \
      "$SRC_DIR/.env.example" | write_file "$SG_ENV" 0640 root:smartguard
  ok "Creado $SG_ENV con secretos aleatorios (AUDIT_MODE=true)"
else
  ok "Se conserva $SG_ENV existente"
  [ "$(env_get AUDIT_MODE)" = true ] || warn "AUDIT_MODE en $SG_ENV no es true: SmartGuard BLOQUEARÁ. (Esperado solo si ya validaste en AUDIT.)"
fi
for f in rules.yaml sites.yaml bots.yaml; do
  if [ ! -f "$SG_ETC/$f" ]; then
    run install -o root -g smartguard -m 0640 "$SRC_DIR/config/$f" "$SG_ETC/$f"
  else
    ok "Se conserva $SG_ETC/$f"
  fi
done

# -----------------------------------------------------------------------------
# 7. Nginx
# -----------------------------------------------------------------------------
log "Instalando snippets de Nginx…"
# Archivos de "código" (se actualizan siempre; el backup ya está hecho)
for f in maps.conf server.conf auth.conf auth-php.conf static-log.conf log-format.conf upstream.conf; do
  run install -o root -g root -m 0644 "$SRC_DIR/nginx/smartguard/$f" "$NGX_SG/$f"
done
# Archivos editables/generados (solo si no existen)
for f in rate-limits.conf cloudflare-realip.conf cloudflare-geo.conf; do
  [ -f "$NGX_SG/$f" ] || run install -o root -g root -m 0644 "$SRC_DIR/nginx/smartguard/$f" "$NGX_SG/$f"
done
if [ "$DRY_RUN" != true ]; then
  gen_mode_conf audit off | write_file "$NGX_SG/mode.conf" 0644
  gen_limits_mode_conf audit | write_file "$NGX_SG/limits-mode.conf" 0644
  gen_allowlist_conf | write_file "$NGX_SG/allowlist.conf" 0644
  gen_secret_conf | write_file "$NGX_SG/secret.conf" 0600 root:root
else
  echo "[dry-run] generaría mode.conf (AUDIT), limits-mode.conf (dry_run on), allowlist.conf, secret.conf"
fi

if [ "$REALIP_EXISTS" = true ]; then
  sed 's|^include /etc/nginx/smartguard/cloudflare-realip.conf;|# (desactivado por install.sh: ya existe real_ip en Nginx)\n# include /etc/nginx/smartguard/cloudflare-realip.conf;|' \
    "$SRC_DIR/nginx/conf.d/smartguard.conf" | write_file "$NGX_CONFD" 0644
else
  run install -o root -g root -m 0644 "$SRC_DIR/nginx/conf.d/smartguard.conf" "$NGX_CONFD"
fi

# Rangos Cloudflare actualizados (si falla, queda la instantánea incluida)
if [ "$DRY_RUN" != true ]; then
  "$SG_OPT/scripts/update-cloudflare-ips.sh" --no-reload || warn "No se pudieron descargar los rangos de Cloudflare; se usa la instantánea incluida."
fi

if ! nginx_safe_reload; then
  warn "Revirtiendo la configuración de Nginx de SmartGuard…"
  run rm -f "$NGX_CONFD"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  die "Nginx rechazó la configuración. Nada cambió en el tráfico. Backup: $BACKUP_PATH"
fi

# -----------------------------------------------------------------------------
# 8. logrotate, systemd, CLI
# -----------------------------------------------------------------------------
run install -o root -g root -m 0644 "$SRC_DIR/logrotate/smartguard-nginx" /etc/logrotate.d/smartguard-nginx
run install -o root -g root -m 0755 "$SRC_DIR/bin/smartguard" "$SG_CLI"
run install -o root -g root -m 0750 "$SRC_DIR/scripts/smartguard-fw-sync" "$SG_FWSYNC"

run install -d -o root -g root -m 0755 "$SG_NGXVIEW" "$SG_NGXVIEW/sites-enabled" "$SG_NGXVIEW/conf.d"
sed "s|^ExecStart=/usr/bin/node |ExecStart=$NODE_BIN |" "$SRC_DIR/systemd/smartguard.service" \
  | write_file /etc/systemd/system/smartguard.service 0644
run install -o root -g root -m 0644 "$SRC_DIR/systemd/smartguard-cf-ips.service" /etc/systemd/system/smartguard-cf-ips.service
run install -o root -g root -m 0644 "$SRC_DIR/systemd/smartguard-cf-ips.timer" /etc/systemd/system/smartguard-cf-ips.timer

# nftables: archivos siempre copiados; activación solo con --enable-nftables
run install -o root -g smartguard -m 0640 "$SRC_DIR/nftables/smartguard.nft" "$SG_ETC/nftables/smartguard.nft"
run install -o root -g smartguard -m 0640 "$SRC_DIR/nftables/origin-lock.nft" "$SG_ETC/nftables/origin-lock.nft"
if [ "$ENABLE_NFT" = true ]; then
  run nft -c -f "$SG_ETC/nftables/smartguard.nft"
  run install -o root -g root -m 0644 "$SRC_DIR/systemd/smartguard-nft.service" /etc/systemd/system/smartguard-nft.service
  run install -d -m 0755 /etc/systemd/system/smartguard.service.d
  run install -o root -g root -m 0644 "$SRC_DIR/systemd/smartguard.service.d/nftables.conf" /etc/systemd/system/smartguard.service.d/nftables.conf
  env_set ENABLE_NFTABLES true
fi

run systemctl daemon-reload
[ "$ENABLE_NFT" = true ] && run systemctl enable --now smartguard-nft.service
run systemctl enable --now smartguard-cf-ips.timer
run systemctl enable smartguard.service
run systemctl restart smartguard.service

# -----------------------------------------------------------------------------
# 9. Verificación
# -----------------------------------------------------------------------------
if [ "$DRY_RUN" != true ]; then
  PORT=$(env_get PORT); PORT=${PORT:-3100}
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then break; fi
    sleep 1
  done
  if curl -fsS "http://127.0.0.1:$PORT/health"; then
    echo; ok "SmartGuard responde en 127.0.0.1:$PORT"
  else
    warn "SmartGuard no responde aún. Revisa: journalctl -u smartguard -n 50 --no-pager"
  fi
  printf 'installed_at=%s\nversion=%s\nbackup=%s\nnode=%s\nrealip=%s\nnftables=%s\n' \
    "$(date -Is)" "$(cd "$SG_OPT" && "$NODE_BIN" -p 'require("./package.json").version')" "$BACKUP_PATH" "$NODE_BIN" \
    "$([ "$REALIP_EXISTS" = true ] && echo existing || echo smartguard)" "$ENABLE_NFT" \
    | write_file "$SG_ETC/.install-manifest" 0640 root:smartguard
fi

cat <<EOF

${C_GRN}${C_BLD}SmartGuard instalado en modo AUDIT.${C_RST}

Siguientes pasos (docs/02-PROCEDIMIENTOS.md):
  1. Añade tu IP de administración:   sudo nano $SG_ENV   (ADMIN_ALLOWLIST=…)
     y aplica:                        sudo smartguard nginx-sync && sudo systemctl restart smartguard
  2. Añade los include de SmartGuard a tu vhost en CloudPanel (Sites → tu sitio → Vhost;
     ver docs/02-PROCEDIMIENTOS.md 13.5). CloudPanel hará nginx -t antes de aplicar.
  3. Comprueba:                       sudo smartguard status
  4. Deja AUDIT 24–72 h y revisa:     sudo smartguard report
  5. Activa protección:               sudo smartguard audit off

Rollback de Nginx:                    sudo $SG_OPT/scripts/rollback-nginx.sh --disable
Backup previo:                        ${BACKUP_PATH:-(dry-run)}
EOF
