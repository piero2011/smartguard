# SmartGuard — Nginx with the SmartGuard snippets, for the Docker Compose stack.
# Build context is the repository root:  docker build -f docker/nginx/Dockerfile -t smartguard-nginx .
# The official image already includes http_auth_request_module and http_realip_module.
FROM nginx:stable

# Snippets (rules, limits, log format, auth_request locations) and the http-level include file.
COPY nginx/smartguard /opt/smartguard/nginx/smartguard
COPY nginx/conf.d/smartguard.conf /opt/smartguard/nginx/http.conf
# Runs at container start (after the image's own template step): writes the files that depend on
# the environment — secret, upstream, AUDIT/ENFORCE mode and allowlist.
COPY docker/nginx/40-smartguard.sh /docker-entrypoint.d/40-smartguard.sh
# Site definition; ${SERVER_NAME} and ${APP_UPSTREAM} are replaced at start. Mount your own
# file over /etc/nginx/templates/site.conf.template to customize it.
COPY docker/nginx/templates /etc/nginx/templates

# Line endings are normalized in case the repository was checked out on Windows (CRLF breaks sh).
RUN sed -i 's/\r$//' /docker-entrypoint.d/40-smartguard.sh /etc/nginx/templates/*.template \
      /opt/smartguard/nginx/http.conf /opt/smartguard/nginx/smartguard/*.conf \
 && chmod +x /docker-entrypoint.d/40-smartguard.sh \
 && rm -f /etc/nginx/conf.d/default.conf \
 && mkdir -p /etc/nginx/smartguard /var/log/nginx/smartguard
