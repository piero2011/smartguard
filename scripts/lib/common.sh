#!/usr/bin/env bash
# =============================================================================
# SmartGuard — funciones comunes de los scripts (source, no ejecutar)
# =============================================================================

SG_OPT=/opt/smartguard
SG_ETC=/etc/smartguard
SG_ENV=$SG_ETC/smartguard.env
SG_VAR=/var/lib/smartguard
# Copia de trabajo de GitHub que usa "smartguard update" (propiedad de root)
SG_SRC=/opt/smartguard-src
SG_LOGDIR=/var/log/nginx/smartguard
NGX_DIR=/etc/nginx
NGX_SG=$NGX_DIR/smartguard
# Archivo de contexto http de SmartGuard: lo fija resolve_http_conf (conf.d o sites-enabled)
NGX_CONFD=${NGX_CONFD:-}
NGX_BACKUPS=$NGX_DIR/backups
SG_CLI=/usr/local/bin/smartguard
SG_FWSYNC=/usr/local/sbin/smartguard-fw-sync

DRY_RUN=${DRY_RUN:-false}
ASSUME_YES=${ASSUME_YES:-false}

if [ -t 1 ]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YLW=$'\e[33m'; C_BLU=$'\e[34m'; C_BLD=$'\e[1m'; C_RST=$'\e[0m'
else
  C_RED=; C_GRN=; C_YLW=; C_BLU=; C_BLD=; C_RST=
fi

log()  { printf '%s[smartguard]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_YLW" "$C_RST" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Este script debe ejecutarse como root (sudo)."
}

# Ejecuta un comando o lo muestra en --dry-run. Uso: run cmd args...
run() {
  if [ "$DRY_RUN" = true ]; then
    printf '%s[dry-run]%s %s\n' "$C_YLW" "$C_RST" "$*"
  else
    "$@"
  fi
}

# Escribe stdin en un archivo de forma atómica (tmp + mv) con modo/propietario. Respeta --dry-run.
# Uso: some_command | write_file /ruta 0644 root:root
write_file() {
  local dest=$1 mode=${2:-0644} owner=${3:-root:root} tmp
  if [ "$DRY_RUN" = true ]; then
    printf '%s[dry-run]%s escribiría %s (%s %s):\n' "$C_YLW" "$C_RST" "$dest" "$mode" "$owner"
    sed -n -e 's/^/    | /' -e '1,40p'
    return 0
  fi
  tmp=$(mktemp "$(dirname "$dest")/.sg.XXXXXX")
  cat >"$tmp"
  chmod "$mode" "$tmp"
  chown "$owner" "$tmp"
  mv -f "$tmp" "$dest"
}

confirm() {
  local prompt=$1
  if [ "$ASSUME_YES" = true ] || [ "$DRY_RUN" = true ]; then return 0; fi
  read -r -p "$prompt [s/N] " ans
  case "$ans" in s|S|si|SI|y|Y|yes) return 0 ;; *) return 1 ;; esac
}

# Lee una variable del .env SIN ejecutarlo (nunca "source" de archivos de config).
env_get() {
  local key=$1 file=${2:-$SG_ENV}
  [ -r "$file" ] || { echo ""; return 0; }
  grep -E "^${key}=" "$file" | tail -n1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

# Cambia (o añade) KEY=VALUE en el .env. VALUE solo admite caracteres seguros.
env_set() {
  local key=$1 value=$2 file=${3:-$SG_ENV}
  [[ "$value" =~ ^[A-Za-z0-9_.,:/@+=-]*$ ]] || die "Valor no permitido para $key"
  if [ "$DRY_RUN" = true ]; then echo "[dry-run] $file: $key=$value"; return 0; fi
  if grep -qE "^${key}=" "$file"; then
    sed -i -E "s|^${key}=.*$|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

# Backup completo de /etc/nginx (excepto los propios backups). Devuelve la ruta en BACKUP_PATH.
backup_nginx() {
  local tag=${1:-manual}
  local ts; ts=$(date +%Y%m%d-%H%M%S)
  BACKUP_PATH="$NGX_BACKUPS/nginx-$ts-$tag.tar.gz"
  run install -d -m 0700 "$NGX_BACKUPS"
  if [ "$DRY_RUN" = true ]; then
    echo "[dry-run] tar czf $BACKUP_PATH -C /etc --exclude=nginx/backups nginx"
    return 0
  fi
  tar czf "$BACKUP_PATH" -C /etc --exclude=nginx/backups nginx
  chmod 0600 "$BACKUP_PATH"
  ok "Backup de /etc/nginx: $BACKUP_PATH"
}

# nginx -t && reload. Si -t falla NO recarga y devuelve 1 (punto 46).
nginx_safe_reload() {
  if [ "$DRY_RUN" = true ]; then echo "[dry-run] nginx -t && systemctl reload nginx"; return 0; fi
  local out
  out=$(mktemp)
  if nginx -t 2>"$out"; then
    rm -f "$out"
    systemctl reload nginx
    ok "nginx -t correcto; Nginx recargado"
    return 0
  fi
  warn "nginx -t FALLÓ; NO se recarga Nginx:"
  sed 's/^/    /' "$out" >&2
  rm -f "$out"
  return 1
}

# Validaciones estrictas de IP/CIDR (para nft y geo de Nginx)
is_cidr_v4() {
  local v=$1 ip pfx o
  [[ "$v" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]{1,2}))?$ ]] || return 1
  for o in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
    [ "$((10#$o))" -le 255 ] || return 1
  done
  pfx=${BASH_REMATCH[6]:-32}
  [ "$((10#$pfx))" -le 32 ]
}
is_cidr_v6() {
  local v=$1
  [[ "$v" =~ ^[0-9a-fA-F:]{2,39}(/([0-9]{1,3}))?$ ]] || return 1
  [[ "$v" == *:* ]] || return 1
  local pfx=${BASH_REMATCH[2]:-128}
  [ "$((10#$pfx))" -le 128 ]
}

is_domain() {
  [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

# Convierte valores de allowlist (stdin, uno por línea) en IPs/CIDR para Nginx y nftables:
#   IP/CIDR → tal cual · dominio exacto → sus IPs actuales (getent) · *.dominio → se omite
#   (los subdominios solo los puede verificar SmartGuard por FCrDNS, Nginx/nft no hacen DNS).
expand_allow_values() {
  local e ip
  while read -r e; do
    e=${e// /}
    [ -z "$e" ] && continue
    if is_cidr_v4 "$e" || is_cidr_v6 "$e"; then
      echo "$e"
    elif [[ "$e" == \*.* || "$e" == .* ]]; then
      warn "  $e: subdominios solo se aplican en SmartGuard (FCrDNS), no en Nginx/nftables"
    elif is_domain "$e"; then
      getent ahosts "$e" 2>/dev/null | awk '{print $1}' | sort -u | while read -r ip; do
        if is_cidr_v4 "$ip" || is_cidr_v6 "$ip"; then echo "$ip"; fi
      done || true   # un dominio que no resuelve no debe abortar (pipefail)
    else
      warn "Entrada de allowlist inválida ignorada: $e"
    fi
  done
}

# Lista (una por línea) las entradas de las allowlists del .env, ya expandidas a IPs/CIDR.
allowlist_entries() {
  local raw
  raw="$(env_get ADMIN_ALLOWLIST),$(env_get SERVICE_ALLOWLIST),$(env_get TRUSTED_NETWORKS)"
  tr ',' '\n' <<<"$raw" | expand_allow_values
}

# Dónde va el archivo de contexto http de SmartGuard.
#   /etc/nginx/conf.d/smartguard.conf            si nginx.conf incluye conf.d/*.conf
#   /etc/nginx/sites-enabled/00-smartguard.conf  si solo incluye sites-enabled/*.conf (CloudPanel)
resolve_http_conf() {
  local t
  if [ -f "$NGX_DIR/conf.d/smartguard.conf" ]; then NGX_CONFD="$NGX_DIR/conf.d/smartguard.conf"; return 0; fi
  if [ -f "$NGX_DIR/sites-enabled/00-smartguard.conf" ]; then NGX_CONFD="$NGX_DIR/sites-enabled/00-smartguard.conf"; return 0; fi
  t=$(nginx -T 2>/dev/null || true)
  if grep -qE 'include[[:space:]]+/etc/nginx/conf\.d/\*\.conf' <<<"$t"; then
    NGX_CONFD="$NGX_DIR/conf.d/smartguard.conf"
  elif grep -qE 'include[[:space:]]+/etc/nginx/sites-enabled/\*(\.conf)?;' <<<"$t"; then
    NGX_CONFD="$NGX_DIR/sites-enabled/00-smartguard.conf"
  else
    NGX_CONFD=""
    return 1
  fi
}

# Instala el dashboard Angular compilado en <stage>/dashboard/dist/browser.
# Usa el build incluido en el paquete (dashboard/dist/browser) o, si no existe, lo compila en un
# directorio temporal (npm ci --ignore-scripts + ng build). Si falla, SmartGuard funciona igual
# (solo sin dashboard): nunca aborta la instalación por esto.
install_dashboard() {
  local src=$1 stage=$2 tmp
  if [ -f "$src/dashboard/dist/browser/index.html" ]; then
    install -d "$stage/dashboard/dist"
    cp -a "$src/dashboard/dist/browser" "$stage/dashboard/dist/"
    ok "Dashboard Angular incluido (build existente)"
    return 0
  fi
  if [ ! -f "$src/dashboard/package.json" ]; then
    warn "Dashboard no incluido en el paquete (SmartGuard funciona sin él)"
    return 0
  fi
  log "Compilando dashboard Angular…"
  tmp=$(mktemp -d)
  cp -a "$src/dashboard/." "$tmp/"
  rm -rf "$tmp/node_modules" "$tmp/dist"
  if ( cd "$tmp" && npm ci --ignore-scripts --no-audit --no-fund && npx --no-install ng build ); then
    install -d "$stage/dashboard/dist"
    cp -a "$tmp/dist/browser" "$stage/dashboard/dist/"
    ok "Dashboard Angular compilado"
  else
    warn "No se pudo compilar el dashboard (SmartGuard funciona sin él; compílalo en tu PC con: cd dashboard && npm ci && npx ng build)"
  fi
  rm -rf "$tmp"
}

node_bin() {
  local n
  n=$(command -v node || true)
  if [ -n "$n" ]; then readlink -f "$n"; fi
}
