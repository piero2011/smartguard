#!/usr/bin/env bash
# SmartGuard — recarga segura (punto 46): nginx -t && systemctl reload nginx. Si -t falla, NO recarga.
set -Eeuo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SELF_DIR/lib/common.sh"
[ "${1:-}" = --dry-run ] && DRY_RUN=true
require_root
nginx_safe_reload
