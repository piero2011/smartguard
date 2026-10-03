#!/usr/bin/env bash
# =============================================================================
# SmartGuard — pruebas de carga (punto 53): baseline vs SmartGuard activo
# =============================================================================
# Requiere oha (recomendado), wrk o hey:
#   apt-get install -y wrk        # o: cargo install oha / descargar binario de oha
#
# Uso:
#   sudo loadtest.sh decision [--duration 30s] [--concurrency 50]
#       Micro-benchmark de GET /internal/decision (camino completo: reglas + Redis Lua),
#       con una IP normal y con una IP baneada (camino rápido).
#   sudo loadtest.sh e2e --host tudominio.com --path '/?sg_bench=1' [--duration 30s] [--concurrency 20]
#       Extremo a extremo por Nginx (http://127.0.0.1, Host: tudominio.com) comparando:
#         A) killswitch ON  → Nginx no consulta a SmartGuard (baseline)
#         B) killswitch OFF → SmartGuard activo
#       Usa una URL dinámica (va a PHP). ¡Genera carga real en PHP-FPM! Hazlo fuera de horas punta.
#       Nota: desde loopback la IP es 127.0.0.1 (TRUSTED) → no se aplican limit_req de SmartGuard.
#
# Mide: req/s, latencia p50/p95/p99 (de la herramienta) + CPU% y RSS de node/nginx/php-fpm/redis.
# =============================================================================
set -Eeuo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SELF_DIR/lib/common.sh"
require_root

SUB=${1:-help}; shift || true
DUR=30s; CONC=50; HOSTN=""; PATHQ='/?sg_bench=1'
while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DUR=$2; shift ;;
    --concurrency) CONC=$2; shift ;;
    --host) HOSTN=$2; shift ;;
    --path) PATHQ=$2; shift ;;
    *) die "Opción desconocida: $1" ;;
  esac
  shift
done
[[ "$DUR" =~ ^[0-9]+s$ ]] || die "--duration como 30s"
[[ "$CONC" =~ ^[0-9]+$ ]] || die "--concurrency numérico"
SECS=${DUR%s}

RA=$(mktemp); RB=$(mktemp); RS=$(mktemp); trap 'rm -f "$RA" "$RB" "$RS"' EXIT
TOOL=""
for t in oha wrk hey; do command -v "$t" >/dev/null && { TOOL=$t; break; }; done
[ -n "$TOOL" ] || die "Instala oha, wrk o hey."

# Muestra CPU% medio y RSS máximo de procesos durante la prueba
sample_resources() {
  local secs=$1 out=$2
  : >"$out"
  for _ in $(seq 1 "$secs"); do
    ps -eo comm=,pcpu=,rss= | awk '$1 ~ /^(node|nginx|php-fpm|redis-server)/ {c[$1]+=$2; r[$1]+=$3} END {for (k in c) printf "%s %.1f %d\n", k, c[k], r[k]}' >>"$out"
    sleep 1
  done
}
summarize_resources() {
  awk '{c[$1]+=$2; n[$1]++; if ($3>r[$1]) r[$1]=$3} END {for (k in c) printf "  %-14s CPU medio %6.1f%%   RSS máx %7.1f MB\n", k, c[k]/n[k], r[k]/1024}' "$1"
}

# run_load URL [headers...]
run_load() {
  local url=$1; shift
  local hdrs=("$@")
  case "$TOOL" in
    oha)
      local a=(); for h in "${hdrs[@]}"; do a+=(-H "$h"); done
      oha --no-tui --insecure -z "$DUR" -c "$CONC" "${a[@]}" "$url" | grep -E 'Requests/sec|Slowest|Fastest|Average|50(\.00)?%|95(\.00)?%|99(\.00)?%|Status code|\[' | head -n 20 ;;
    wrk)
      local a=(); for h in "${hdrs[@]}"; do a+=(-H "$h"); done
      wrk -t4 -c "$CONC" -d "$DUR" --latency "${a[@]}" "$url" | grep -E 'Requests/sec|Latency|50%|90%|99%|Non-2xx' ;;
    hey)
      local a=(); for h in "${hdrs[@]}"; do a+=(-H "$h"); done
      hey -z "$DUR" -c "$CONC" "${a[@]}" "$url" | grep -E 'Requests/sec|50%|95%|99%|\[[0-9]{3}\]' ;;
  esac
}

case "$SUB" in
  decision)
    PORT=$(env_get PORT); PORT=${PORT:-3100}; KEY=$(env_get DECISION_SHARED_SECRET)
    COMMON=("X-SmartGuard-Key: $KEY" "X-TCP-IP: 172.64.0.1" "X-Original-Method: GET" "X-User-Agent: Mozilla/5.0 bench" "X-Host: orleansembroidery.com")
    log "1) IP normal, ruta normal (camino completo: reglas + 1 EVALSHA)"
    sample_resources "$SECS" "$RA" & SP=$!
    run_load "http://127.0.0.1:$PORT/internal/decision" "${COMMON[@]}" "X-Real-IP: 198.51.100.200" "X-Original-URI: /product/test/?color=azul"
    wait $SP; summarize_resources "$RA"
    log "2) IP baneada (camino rápido)"
    "$SG_CLI" ban 198.51.100.201 10m loadtest >/dev/null
    run_load "http://127.0.0.1:$PORT/internal/decision" "${COMMON[@]}" "X-Real-IP: 198.51.100.201" "X-Original-URI: /"
    "$SG_CLI" unban 198.51.100.201 >/dev/null
    ;;

  e2e)
    [ -n "$HOSTN" ] || die "--host requerido (server_name del sitio)"
    URL="http://127.0.0.1$PATHQ"   # puerto 80 del mismo server (sin TLS: mide Nginx+SmartGuard+PHP)
    warn "Esto genera carga REAL en PHP-FPM durante 2×$DUR contra $HOSTN."
    confirm "¿Continuar?" || die "Cancelado."
    log "A) BASELINE: killswitch ON (Nginx no consulta a SmartGuard)"
    "$SG_CLI" killswitch on >/dev/null
    sample_resources "$SECS" "$RB" & SP=$!
    run_load "$URL" "Host: $HOSTN"
    wait $SP; summarize_resources "$RB"
    log "B) SMARTGUARD ACTIVO: killswitch OFF"
    "$SG_CLI" killswitch off >/dev/null
    sample_resources "$SECS" "$RS" & SP=$!
    run_load "$URL" "Host: $HOSTN"
    wait $SP; summarize_resources "$RS"
    ok "Compara req/s y p95/p99 de A y B. Objetivo: diferencia < 5% y < 2 ms en p99."
    ;;

  *) sed -n '2,22p' "$0" ;;
esac
