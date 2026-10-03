#!/usr/bin/env bash
# =============================================================================
# SmartGuard — generadores de archivos Nginx (source, requiere common.sh)
# =============================================================================

# /etc/nginx/smartguard/mode.conf  ($1 = audit|enforce, $2 = killswitch on|off)
gen_mode_conf() {
  local mode=$1 ks=${2:-off} enforce=0 k=0
  [ "$mode" = enforce ] && enforce=1
  [ "$ks" = on ] && k=1
  cat <<EOF
# /etc/nginx/smartguard/mode.conf — GENERADO por smartguard ($(date -Is)). No editar.
# 0 = AUDIT (reglas Nginx nuevas solo se registran) · 1 = ENFORCE (403)
map \$host \$sg_nginx_enforce {
    default $enforce;
}
# 1 = kill switch: auth_request no consulta a SmartGuard
map \$host \$sg_killswitch {
    default $k;
}
EOF
}

# /etc/nginx/smartguard/limits-mode.conf ($1 = audit|enforce)
gen_limits_mode_conf() {
  local v=on
  [ "$1" = enforce ] && v=off
  cat <<EOF
# /etc/nginx/smartguard/limits-mode.conf — GENERADO por smartguard ($(date -Is)). No editar.
# on = AUDIT (limit_req/limit_conn solo registran REJECTED_DRY_RUN) · off = ENFORCE (429)
limit_req_dry_run $v;
limit_conn_dry_run $v;
EOF
}

# /etc/nginx/smartguard/allowlist.conf desde el .env (+ entradas dinámicas opcionales en $1, una por línea)
gen_allowlist_conf() {
  local extra=${1:-} e
  echo "# /etc/nginx/smartguard/allowlist.conf — GENERADO por smartguard nginx-sync ($(date -Is)). No editar."
  echo "# Fuente: ADMIN_ALLOWLIST, SERVICE_ALLOWLIST, TRUSTED_NETWORKS (+ allowlist dinámica de la API)."
  echo "geo \$sg_trusted {"
  echo "    default 0;"
  echo "    127.0.0.0/8 1;"
  echo "    ::1/128 1;"
  # "if" y no "[ … ] &&": con extra vacío el grupo devolvería 1 y pipefail + set -e abortarían.
  { allowlist_entries; if [ -n "$extra" ]; then printf '%s\n' "$extra" | expand_allow_values; fi; } | sort -u | while read -r e; do
    [ -z "$e" ] && continue
    if is_cidr_v4 "$e" || is_cidr_v6 "$e"; then echo "    $e 1;"; fi
  done
  echo "}"
}

# /etc/nginx/smartguard/secret.conf desde DECISION_SHARED_SECRET
gen_secret_conf() {
  local s
  s=$(env_get DECISION_SHARED_SECRET)
  [[ "$s" =~ ^[A-Za-z0-9]{24,128}$ ]] || die "DECISION_SHARED_SECRET ausente o con caracteres no permitidos en $SG_ENV"
  echo "# GENERADO por smartguard ($(date -Is)). Debe coincidir con DECISION_SHARED_SECRET."
  echo "proxy_set_header X-SmartGuard-Key \"$s\";"
}

# Stubs neutros: dejan los include del vhost válidos pero SmartGuard sin efecto en Nginx.
write_neutral_stubs() {
  echo "# SmartGuard DESACTIVADO en Nginx ($(date -Is)). Archivo neutro." | write_file "$NGX_SG/server.conf" 0644
  echo "# SmartGuard DESACTIVADO en Nginx ($(date -Is)). Archivo neutro." | write_file "$NGX_SG/auth.conf" 0644
  echo "# SmartGuard DESACTIVADO en Nginx ($(date -Is)). Archivo neutro (sin auth_request)." | write_file "$NGX_SG/auth-php.conf" 0644
  printf '# SmartGuard DESACTIVADO: comportamiento original\naccess_log off;\n' | write_file "$NGX_SG/static-log.conf" 0644
}
