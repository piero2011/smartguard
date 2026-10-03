#!/bin/sh
# SmartGuard — prepares /etc/nginx/smartguard inside the Nginx container at start.
# Static snippets come from the image; this script writes the ones that depend on the environment:
#   secret.conf        DECISION_SHARED_SECRET (must match the smartguard service)
#   upstream.conf      where the smartguard service listens (SMARTGUARD_UPSTREAM)
#   mode.conf / limits-mode.conf   AUDIT_MODE (true = only log, false = block)
#   allowlist.conf     IPs/CIDRs of ADMIN_ALLOWLIST, SERVICE_ALLOWLIST, TRUSTED_NETWORKS
set -eu

SRC=/opt/smartguard/nginx
DST=/etc/nginx/smartguard
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mkdir -p "$DST" /var/log/nginx/smartguard
cp "$SRC"/smartguard/*.conf "$DST"/
cp "$SRC"/http.conf /etc/nginx/conf.d/00-smartguard.conf
rm -f /etc/nginx/conf.d/default.conf

# --- secret shared with the smartguard service
secret=${DECISION_SHARED_SECRET:-}
if ! printf '%s' "$secret" | grep -Eq '^[A-Za-z0-9]{24,128}$'; then
  echo "smartguard: DECISION_SHARED_SECRET is missing or invalid (24-128 letters/digits). Generate one with: openssl rand -hex 32" >&2
  exit 1
fi
printf '# Generated at %s. Must match DECISION_SHARED_SECRET.\nproxy_set_header X-SmartGuard-Key "%s";\n' "$NOW" "$secret" >"$DST/secret.conf"
chmod 600 "$DST/secret.conf"

# --- where the decision service is
cat >"$DST/upstream.conf" <<EOF
# Generated at $NOW.
upstream smartguard_backend {
    server ${SMARTGUARD_UPSTREAM:-smartguard:3100};
    keepalive 16;
    keepalive_requests 10000;
    keepalive_timeout 60s;
}
EOF

# --- AUDIT (only log) or ENFORCE (block) for the Nginx rules and limits
case "${AUDIT_MODE:-true}" in
  false|FALSE|0|no) enforce=1; dry=off ;;
  *) enforce=0; dry=on ;;
esac
case "${SMARTGUARD_KILLSWITCH:-off}" in on|ON|1|true) kill=1 ;; *) kill=0 ;; esac
cat >"$DST/mode.conf" <<EOF
# Generated at $NOW. 0 = AUDIT (new Nginx rules only log) · 1 = ENFORCE (403)
map \$host \$sg_nginx_enforce {
    default $enforce;
}
# 1 = kill switch: auth_request does not ask SmartGuard
map \$host \$sg_killswitch {
    default $kill;
}
EOF
cat >"$DST/limits-mode.conf" <<EOF
# Generated at $NOW. on = AUDIT (limits only log REJECTED_DRY_RUN) · off = ENFORCE (429)
limit_req_dry_run $dry;
limit_conn_dry_run $dry;
EOF

# --- clients exempt from the Nginx limits. Only IPs and CIDRs: domains are resolved by the service.
{
  echo "# Generated at $NOW from ADMIN_ALLOWLIST, SERVICE_ALLOWLIST and TRUSTED_NETWORKS."
  echo "geo \$sg_trusted {"
  echo "    default 0;"
  echo "    127.0.0.0/8 1;"
  echo "    ::1/128 1;"
  printf '%s,%s,%s' "${ADMIN_ALLOWLIST:-}" "${SERVICE_ALLOWLIST:-}" "${TRUSTED_NETWORKS:-}" | tr ',' '\n' | tr -d ' \t\r' | sort -u | while read -r e; do
    [ -n "$e" ] || continue
    if printf '%s' "$e" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(/[0-9]{1,3})?$'; then
      echo "    $e 1;"
    fi
  done
  echo "}"
} >"$DST/allowlist.conf"

echo "smartguard: Nginx snippets ready in $DST (mode: $([ "$enforce" = 1 ] && echo ENFORCE || echo AUDIT))"
