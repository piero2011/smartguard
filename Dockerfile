# SmartGuard — decision service + dashboard (the Nginx side is docker/nginx/Dockerfile).
# Build:  docker build -t smartguard .
# Guide:  docs/docker.md (English) · docs/docker.es.md (español)

# --- 1. Service (NestJS) -----------------------------------------------------
FROM node:22-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

# --- 2. Dashboard (Angular) --------------------------------------------------
FROM node:22-bookworm-slim AS dashboard
WORKDIR /dash
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY dashboard ./
RUN npx ng build

# --- 3. Runtime --------------------------------------------------------------
FROM node:22-bookworm-slim
ARG GIT_COMMIT=""
ENV NODE_ENV=production \
    PORT=3100 \
    CONFIG_DIR=/etc/smartguard \
    ANALYZER_STATE_FILE=/var/lib/smartguard/analyzer.state \
    ANALYZER_LOG_PATH=/var/log/nginx/smartguard/access.json

WORKDIR /opt/smartguard
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
COPY package.json ./
# Default rules, sites and bots. Files placed in /etc/smartguard (a volume) take precedence.
COPY config ./config
COPY --from=dashboard /dash/dist/browser ./dashboard/dist/browser

# The service runs as the unprivileged "node" user and only writes to /var/lib/smartguard.
RUN mkdir -p /etc/smartguard /var/lib/smartguard /var/log/nginx/smartguard \
 && chown node:node /var/lib/smartguard \
 && if [ -n "$GIT_COMMIT" ]; then echo "$GIT_COMMIT" > COMMIT; fi
USER node

EXPOSE 3100
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=4 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3100)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--enable-source-maps", "--max-old-space-size=256", "dist/main.js"]
