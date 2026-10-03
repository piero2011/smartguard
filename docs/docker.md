# SmartGuard with Docker and Docker Compose

**English** · [Español](docker.es.md)

This guide runs SmartGuard as containers: an **Nginx** with the SmartGuard rules, the **SmartGuard**
decision service with its dashboard, and **Redis**, all in front of your application.

> **Status.** These files were written and reviewed without a Docker engine available. The container
> start script and the service were tested separately, but the complete stack has not been started
> with `docker compose up` yet. Follow the [checklist](#8-checklist-after-the-first-start) the first
> time and start in AUDIT mode (the default), which blocks nothing.

## 1. What you get

```
Internet ──► nginx (port 80) ──► your application (WordPress, …)
               │  ▲
   auth_request│  │allow / block
               ▼  │
            smartguard ──► redis
          (dashboard on 127.0.0.1:3100)
```

| Service | Image | Role |
|---|---|---|
| `nginx` | built from `docker/nginx/Dockerfile` (official `nginx:stable` + SmartGuard snippets) | Receives the traffic, applies the Nginx rules and limits, asks SmartGuard before passing a request to the application |
| `smartguard` | built from `Dockerfile` | Decision service, log analyzer, admin API and dashboard |
| `redis` | `redis:7-alpine` | Reputation, bans, lists and statistics |
| `wordpress` + `db` | `wordpress:6-apache`, `mariadb:11` | **Demo only** (profile `demo`): an application to try the stack with |

Volumes: `redis_data`, `smartguard_data` (dashboard rules, analyzer state), `nginx_logs` (security
log shared by Nginx and SmartGuard), `nginx_conf` (generated site configuration).

## 2. Requirements

- Docker Engine 24 or later with the Compose plugin (`docker compose version`).
- Linux host. On Docker Desktop (Windows/macOS) the stack runs, but Nginx does not see the visitors'
  real IP, so use it only for trying things out.
- Port 80 free on the host (or change `HTTP_PORT`).

## 3. Quick start

```bash
git clone https://github.com/piero2011/smartguard.git
cd smartguard
cp docker/env.example .env
```

Edit `.env` and set the two secrets (generate each with `openssl rand -hex 32`):

```
ADMIN_TOKEN=…                  # to open the dashboard
DECISION_SHARED_SECRET=…       # shared by Nginx and SmartGuard
```

Then start it. To try it with the demo WordPress:

```bash
docker compose --profile demo up -d --build
```

Open `http://localhost/` (the WordPress installer appears) and the dashboard at
`http://127.0.0.1:3100/dashboard/`, with the `ADMIN_TOKEN` as the access token.

To put it in front of **your own application**, set these in `.env` and start without the demo profile:

```
SERVER_NAME=shop.com www.shop.com
APP_UPSTREAM=http://my-app:8080
```

```bash
docker compose up -d --build
```

## 4. Connecting your application

`APP_UPSTREAM` is where Nginx sends the requests that SmartGuard allows. The address must be reachable
from the `nginx` container:

| Your application runs… | `APP_UPSTREAM` |
|---|---|
| as a service you add to this `docker-compose.yml` (same network) | `http://service-name:port` |
| in another Compose project | attach it to the `smartguard_smartguard` network (`docker network connect`), then `http://container-name:port` |
| on the Docker host itself | `http://172.30.77.1:port` (the gateway of the Compose network is the host; the application must listen on that address or on `0.0.0.0`) |
| on another machine | `http://10.0.0.5:8080` |

The site definition is `docker/nginx/templates/site.conf.template`. It sends everything through
SmartGuard except static files (images, CSS, JS, fonts). To change it — several sites, other static
types, your own headers — edit that file and rebuild (`docker compose up -d --build nginx`), or mount
your own file over `/etc/nginx/templates/site.conf.template`.

**HTTPS.** The stack listens on plain HTTP (port 80). Put it behind something that terminates TLS:
Cloudflare, a load balancer, or a reverse proxy on the host. `X-Forwarded-Proto` from that proxy is
passed on to the application. To terminate TLS in this Nginx instead, add a `listen 443 ssl` server
with your certificates to the template and publish port 443.

**Real visitor IP.** Behind Cloudflare, the real IP is taken from `CF-Connecting-IP` (only when the
connection really comes from Cloudflare). Behind another proxy, add its address with
`set_real_ip_from` and `real_ip_header` in the template; otherwise every visitor would share the
proxy's IP and SmartGuard would score them as one.

## 5. Configuration

Everything is set in `.env` (see `docker/env.example`):

| Variable | Default | What it does |
|---|---|---|
| `ADMIN_TOKEN` | — (required) | Dashboard and admin API token, at least 32 characters |
| `DECISION_SHARED_SECRET` | — (required) | Secret between Nginx and SmartGuard, 24–128 letters and digits |
| `SERVER_NAME` | `_` | Domains served by Nginx |
| `APP_UPSTREAM` | `http://wordpress:80` | Your application |
| `HTTP_PORT` | `80` | Port published for the site |
| `DASHBOARD_PORT` | `3100` | Dashboard port, published on `127.0.0.1` only |
| `AUDIT_MODE` | `true` | `true` only logs; `false` blocks |
| `ADMIN_ALLOWLIST`, `SERVICE_ALLOWLIST`, `TRUSTED_NETWORKS` | empty | IPs, CIDRs or domains that are never blocked |
| `ALLOW_HOSTS` | empty | Destination hosts SmartGuard does not score |

Any other variable of [.env.example](../.env.example) (score thresholds, ban durations, Cloudflare
API…) can be added to `.env` too; it is passed to the `smartguard` service.

**Your own rules, sites and bots.** Put `rules.yaml`, `sites.yaml`, `bots.yaml` or `rules.d/*.yaml`
in `docker/config/` and restart the service (`docker compose restart smartguard`). Files not present
there fall back to the defaults in the image. Rules can also be created from the dashboard (**Rules**
tab); those live in the `smartguard_data` volume.

**From AUDIT to ENFORCE.** After a day or more in AUDIT, review the **Overview**, **Events** and
**Traffic** tabs. When nothing legitimate is being flagged, set `AUDIT_MODE=false` in `.env` and run
`docker compose up -d`. This recreates both containers so that Nginx and SmartGuard change together.
The button in the dashboard header only switches SmartGuard's own decisions and is remembered in
Redis; if you used it, check that the badge in the header shows the mode you expect.

## 6. Day-to-day

```bash
docker compose ps                         # state of the services
docker compose logs -f smartguard         # SmartGuard log
docker compose logs -f nginx              # Nginx log
docker compose restart smartguard         # after changing docker/config
docker compose up -d                      # after changing .env
docker compose down                       # stop (volumes are kept)
```

Update to a new version:

```bash
git pull
docker compose up -d --build
```

Back up what the dashboard manages (rules, allowlist, manual blocks, bots, networks) from the
**Backup** tab, which downloads a file you can import into another SmartGuard. For a full copy, also
save `.env`, `docker/config/` and the `smartguard_data` and `redis_data` volumes.

## 7. What is different from the server install

The `smartguard` command of the server install manages systemd and the host's Nginx, so it is not
available in the containers. Use these instead:

| On a server | With Docker |
|---|---|
| `smartguard status`, `logs` | `docker compose ps`, `docker compose logs` |
| `smartguard allow`, `ban`, `unban`, `allow-host` | dashboard (**IPs & sites**, **Blocked**, **Allowlist**), or the allowlists in `.env` |
| `smartguard audit on/off` | `AUDIT_MODE` in `.env` + `docker compose up -d` |
| `smartguard protect <site>` | every site in the Nginx template is protected |
| `smartguard update` | `git pull && docker compose up -d --build` |
| `smartguard backup` / `restore` | dashboard **Backup** tab + volumes |
| `smartguard nginx-sync` | automatic at every start of the `nginx` container |

Also not available in Docker: nftables blocking and the origin lock (they act on the host firewall).

The allowlist added from the dashboard exempts clients from SmartGuard's decisions at once. The
exemption from the **Nginx request limits** only covers the IPs and CIDRs written in `.env`, and is
applied when the `nginx` container starts.

## 8. Checklist after the first start

1. `docker compose ps` — the three services are `running` and `smartguard` is `healthy`.
2. `curl -I http://localhost/` — your application answers (200 or a redirect).
3. `curl -s -o /dev/null -w "%{http_code}\n" http://localhost/.env` — in AUDIT it is not blocked by
   SmartGuard; a few seconds later the request appears in the dashboard (**Events**).
4. The dashboard opens at `http://127.0.0.1:3100/dashboard/` and accepts the `ADMIN_TOKEN`.
5. In **Traffic**, the IP shown for your own visit is your real IP, not `172.30.77.x`. If it is a
   container address, see "Real visitor IP" above.
6. Only then set `AUDIT_MODE=false`. Repeat step 3: it must now answer `403`.

If `nginx` does not start, `docker compose logs nginx` shows why; the usual causes are a missing
`DECISION_SHARED_SECRET` or a syntax error in an edited template.

## 9. Without Compose (`docker run`)

The same stack with plain Docker commands:

```bash
docker network create --subnet 172.30.77.0/24 smartguard
docker build -t smartguard .
docker build -t smartguard-nginx -f docker/nginx/Dockerfile .

docker run -d --name redis --network smartguard -v redis_data:/data redis:7-alpine

docker run -d --name smartguard --network smartguard --env-file .env \
  -e BIND_ADDRESS=0.0.0.0 -e ALLOW_NON_LOOPBACK_BIND=true \
  -e LOCAL_NETWORKS=172.30.77.0/24 -e REDIS_HOST=redis \
  -p 127.0.0.1:3100:3100 \
  -v smartguard_data:/var/lib/smartguard \
  -v nginx_logs:/var/log/nginx/smartguard:ro \
  -v nginx_conf:/etc/nginx/conf.d:ro \
  smartguard

docker run -d --name nginx --network smartguard --env-file .env \
  -p 80:80 \
  -v nginx_logs:/var/log/nginx/smartguard \
  -v nginx_conf:/etc/nginx/conf.d \
  smartguard-nginx
```

`--env-file .env` gives both containers the secrets, `SERVER_NAME`, `APP_UPSTREAM` and `AUDIT_MODE`.
Your application must be attached to the same `smartguard` network (or be reachable at the
`APP_UPSTREAM` address).

## 10. Security notes

- The `smartguard` service listens on all interfaces **inside its container**, but only accepts
  connections from loopback and from the Compose network declared in `LOCAL_NETWORKS`
  (`172.30.77.0/24`). The admin API additionally requires the token. Never put a public network there.
- The dashboard port is published on `127.0.0.1` only. To reach it from outside, use an SSH tunnel
  (`ssh -L 3100:127.0.0.1:3100 user@server`) or put an HTTPS reverse proxy with access control in front.
- If you change the subnet in `docker-compose.yml`, change `LOCAL_NETWORKS` to match.
- The service runs as an unprivileged user with every Linux capability dropped.
- The security log (`nginx_logs` volume) is not rotated by the stack. It only receives
  security-relevant lines, so it grows slowly; empty it when needed with
  `docker compose exec nginx sh -c ': > /var/log/nginx/smartguard/access.json'`.
