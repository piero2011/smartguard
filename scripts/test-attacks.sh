#!/usr/bin/env bash
# =============================================================================
# SmartGuard — simulación de ataques SEGURA (punto 54)
# =============================================================================
# Modo 1 (por defecto, recomendado): --decision-api
#   Llama DIRECTAMENTE a la API local de decisión (127.0.0.1) con IPs de documentación
#   (198.51.100.0/24 y 2001:db8::/32, RFC 5737/3849). No genera tráfico HTTP real, no toca PHP,
#   no puede afectar a IPs reales (tampoco llegan a nftables ni a Cloudflare: no son públicas).
#     sudo test-attacks.sh
#     sudo test-attacks.sh --ip 198.51.100.77 --keep
#
# Modo 2: --target URL  (staging o el propio servidor por loopback)
#   Solo se permite contra 127.0.0.1/localhost/::1, o contra un host que confirmes explícitamente
#   con --confirm-staging <host> (escrito igual que en la URL). NUNCA contra terceros.
#     sudo test-attacks.sh --target https://127.0.0.1 --host staging.midominio.com
#     sudo test-attacks.sh --target https://staging.midominio.com --confirm-staging staging.midominio.com
#   Ojo: desde loopback la IP es 127.0.0.1 (TRUSTED_NETWORK) → SmartGuard registra pero nunca banea.
# =============================================================================
set -Eeuo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SELF_DIR/lib/common.sh"

MODE=api; TARGET=""; HOSTHDR=""; CONFIRM=""; TEST_IP="198.51.100.77"; TEST_IP6="2001:db8:5a:1::77"; KEEP=false
while [ $# -gt 0 ]; do
  case "$1" in
    --decision-api) MODE=api ;;
    --target) MODE=http; TARGET=${2:-}; shift ;;
    --host) HOSTHDR=${2:-}; shift ;;
    --confirm-staging) CONFIRM=${2:-}; shift ;;
    --ip) TEST_IP=${2:-}; shift ;;
    --keep) KEEP=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "Opción desconocida: $1" ;;
  esac
  shift
done

SCANNER=(/.env /.git/config /shell.php /phpinfo.php /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php /wp-config.php.bak /backup.sql /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php)
NORMAL=(/ /shop/ /cart/ '/?wc-ajax=get_refreshed_fragments' /my-account/ /wp-json/wc/store/v1/cart /sitemap_index.xml)
PAYLOADS=('/?id=1%20UNION%20SELECT%201,2,3' '/?page=../../../../etc/passwd' '/?q=%3Cscript%3Ealert(1)%3C/script%3E')

if [ "$MODE" = api ]; then
  require_root
  PORT=$(env_get PORT); PORT=${PORT:-3100}
  KEY=$(env_get DECISION_SHARED_SECRET)
  [[ "$TEST_IP" =~ ^198\.51\.100\.[0-9]{1,3}$|^2001:db8: ]] || die "--ip debe ser de documentación (198.51.100.x o 2001:db8::/32)"
  decide() { # ip uri [method] [ua]
    curl -s -o /dev/null -w '%{http_code} %header{x-smartguard-decision} score=%header{x-smartguard-score}' --max-time 3 \
      -H "X-SmartGuard-Key: $KEY" -H "X-Real-IP: $1" -H "X-TCP-IP: 172.64.0.1" -H "X-Original-URI: $2" \
      -H "X-Original-Method: ${3:-GET}" -H "X-User-Agent: ${4:-Mozilla/5.0 (SmartGuard-SelfTest)}" \
      -H "X-Host: orleansembroidery.com" -H "X-Request-ID: sgtest$RANDOM$RANDOM" \
      "http://127.0.0.1:$PORT/internal/decision"
  }
  NORMAL_IP="198.51.100.10"
  log "Navegación normal ($NORMAL_IP) — debe ser 200 ALLOW:"
  for u in "${NORMAL[@]}"; do printf '  %-60s %s\n' "$u" "$(decide "$NORMAL_IP" "$u")"; done
  log "Scanner ($TEST_IP) — debe escalar a BLOCK (o WOULD_BLOCK en AUDIT) en pocas peticiones:"
  for u in "${SCANNER[@]}"; do printf '  %-60s %s\n' "$u" "$(decide "$TEST_IP" "$u" GET 'python-requests/2.31')"; done
  log "Payloads (198.51.100.78):"
  for u in "${PAYLOADS[@]}"; do printf '  %-60s %s\n' "$u" "$(decide 198.51.100.78 "$u")"; done
  log "IPv6 scanner ($TEST_IP6) y otra IP del mismo /64:"
  for u in /.env /.git/config /wso.php; do printf '  %-60s %s\n' "$u" "$(decide "$TEST_IP6" "$u")"; done
  printf '  %-60s %s\n' "/ desde 2001:db8:5a:1::99" "$(decide 2001:db8:5a:1::99 /)"
  log "Googlebot falso (UA Googlebot, IP no de Google):"
  for _ in 1 2; do printf '  %-60s %s\n' "/" "$(decide 198.51.100.79 / GET 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')"; sleep 2; done
  echo; log "Explicación de $TEST_IP:"
  "$SG_CLI" ip "$TEST_IP" || true
  if [ "$KEEP" != true ]; then
    for ip in "$TEST_IP" 198.51.100.78 198.51.100.79 "$TEST_IP6"; do "$SG_CLI" unban "$ip" >/dev/null 2>&1 || true; done
    ok "Bans de prueba eliminados (usa --keep para conservarlos)"
  fi
  exit 0
fi

# ---- Modo HTTP ----
[ -n "$TARGET" ] || die "--target requerido"
[[ "$TARGET" =~ ^https?://([^/:]+|\[[^]]+\])(:[0-9]+)?/?$ ]] || die "URL inválida: $TARGET"
THOST=${BASH_REMATCH[1]}; THOST=${THOST#[}; THOST=${THOST%]}
case "$THOST" in
  127.0.0.1|localhost|::1) ;;
  *) [ -n "$CONFIRM" ] && [ "$CONFIRM" = "$THOST" ] || die "Destino no local. Confirma que es TU staging con --confirm-staging $THOST" ;;
esac
TARGET=${TARGET%/}
H=(); [ -n "$HOSTHDR" ] && H=(-H "Host: $HOSTHDR")
req() { curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${H[@]}" -A "${3:-SmartGuard-SelfTest}" -X "${2:-GET}" "$TARGET$1"; }
log "Normal:";   for u in "${NORMAL[@]}"; do printf '  %-60s %s\n' "$u" "$(req "$u")"; done
log "Scanner:";  for u in "${SCANNER[@]}"; do printf '  %-60s %s\n' "$u" "$(req "$u" GET python-requests/2.31)"; done
log "Payloads:"; for u in "${PAYLOADS[@]}"; do printf '  %-60s %s\n' "$u" "$(req "$u")"; done
log "wp-login POST ×15 (credenciales falsas; en staging):"
for i in $(seq 1 15); do
  printf '%s ' "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${H[@]}" -A SmartGuard-SelfTest \
    --data-urlencode "log=sg-test-user-$i" --data-urlencode "pwd=not-a-real-password-$RANDOM" "$TARGET/wp-login.php")"
done; echo
log "xmlrpc:"; printf '  %s\n' "$(req /xmlrpc.php POST)"
log "Revisa: sudo smartguard events 40 ; sudo smartguard report"
