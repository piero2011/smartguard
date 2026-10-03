# SmartGuard

Capa de seguridad para **WordPress, WooCommerce y WordPress Multisite** que detiene el tráfico
malicioso **antes de que consuma PHP-FPM**. Nginx sigue siendo el servidor frontal; SmartGuard
(NestJS + Redis) es el motor de decisión, scoring, reputación y bans, y solo se consulta para
tráfico que iba a PHP.

> Prioridades de diseño, en orden: no romper WooCommerce · no romper Multisite · evitar PHP ·
> evitar falsos positivos · bajo CPU · bajo Redis · fail-open · IPv4+IPv6 · mantenible · auditable.

- Instalación, AUDIT y ENFORCE paso a paso (FASES 13–15): [docs/02-PROCEDIMIENTOS.md](docs/02-PROCEDIMIENTOS.md)

---

## 1. Arquitectura

```mermaid
flowchart TD
    I[Internet] --> CF[Cloudflare<br/>proxy + IP Access Rules opcionales]
    CF --> NFT[nftables · table inet smartguard<br/>solo IPs TCP directas, nunca Cloudflare]
    NFT --> NG{Nginx}
    NG -->|estático: jpg css js woff mp4…| FILE[Archivo<br/>sin SmartGuard, sin PHP]
    NG -->|ataque obvio: .env .git .sql phpmyadmin<br/>métodos raros · bots malos · payloads| D403[403 / 444<br/>solo Nginx]
    NG -->|abuso de volumen por endpoint<br/>limit_req / limit_conn| D429[429]
    NG -->|dinámico que va a PHP| AUTH[auth_request → SmartGuard<br/>127.0.0.1:3100 · 1 EVALSHA Redis]
    AUTH -->|200 ALLOW / OBSERVE / fail-open| FPM[PHP-FPM]
    AUTH -->|403 BLOCK / RATE_LIMIT| B403[403]
    FPM --> WP[WordPress · WooCommerce · Multisite]
```

```mermaid
flowchart LR
    L[Nginx log JSON<br/>solo líneas de seguridad] --> A[SmartGuard Analyzer<br/>tail asíncrono, lotes de 2 s]
    A --> R[(Redis smartguard:*)]
    AUTH2[auth_request] --> R
    R --> S[scoring + decay]
    R --> RC[reincidencia]
    R --> BAN[bans temporales]
    BAN -. IP TCP directa + evidencia fuerte .-> NFT2[nftables]
    BAN -. reincidente + score muy alto .-> CFAPI[Cloudflare API opcional]
```

**Por qué `auth_request` solo en las `location` con `fastcgi_pass`:** es el único punto por el que
pasa *todo* lo que llega a PHP-FPM (incluidas las redirecciones internas `try_files … /index.php`),
y nada estático pasa por ahí. Así ningún `.php` directo se salta SmartGuard y ninguna imagen genera
una subpetición.

## 2. Estructura

```
smartguard/
├── src/
│   ├── main.ts / app.module.ts     Bootstrap Fastify, validación global, shutdown ordenado
│   ├── config/                     env tipado + YAML (reglas, sitios, bots)
│   ├── common/                     tipos, IP/CIDR (IPv4/IPv6), URI, logger JSON, guards
│   ├── redis/                      conexión + circuit breaker + scripts Lua
│   ├── reputation/                 almacén Redis y almacén en memoria (misma semántica)
│   ├── rules/                      motor de reglas + protección anti-ReDoS
│   ├── scoring/                    decisión, contexto de petición, modo AUDIT/ENFORCE
│   ├── ban/                        BanService (reincidencia, nftables, Cloudflare)
│   ├── bots/                       verificación FCrDNS (Googlebot, Bingbot, Applebot)
│   ├── whitelist/                  allowlists por tipo
│   ├── firewall/                   nftables sin shell (execFile + validación)
│   ├── cloudflare/                 rangos Cloudflare + API opcional
│   ├── logs/                       tail del log JSON + analizador de comportamiento
│   ├── nginx/                      GET /internal/decision (auth_request)
│   ├── admin/                      API administrativa autenticada
│   ├── dashboard/                  sirve el build del dashboard Angular (CSP + nonce)
│   ├── health/ metrics/ stats/ alerts/
├── config/          rules.yaml · sites.yaml · bots.yaml
├── nginx/           conf.d/smartguard.conf (→ sites-enabled/00-smartguard.conf en CloudPanel) · smartguard/*.conf
├── nftables/        smartguard.nft · origin-lock.nft
├── systemd/         smartguard.service (+ drop-in nftables) · smartguard-nft · timer rangos CF
├── scripts/         install · update · uninstall · rollback-nginx · update-cloudflare-ips ·
│                    origin-lock · test-attacks · loadtest · smartguard-fw-sync · lib/
├── dashboard/       Dashboard Angular 22 (standalone, signals, sin zone.js), inglés/español
├── bin/smartguard   CLI
├── logrotate/       smartguard-nginx
├── tests/           unit/ · integration/
└── docs/
```

## 3. Requisitos

| Componente | Versión | Notas |
|---|---|---|
| Debian | 13 | probado para Debian 13 (Trixie) |
| Node.js | ≥ 22 | del sistema (`/usr/bin/node`), no nvm en `/home`. El `nodejs` de apt en Debian 13 es 20.x: usa NodeSource |
| Nginx | ≥ 1.18 | con `http_auth_request_module` y `http_realip_module` |
| Redis | ≥ 6 | opcional en la práctica: sin Redis funciona en memoria (modo degradado) |
| nftables | cualquiera | opcional |

### Dependencias (y por qué cada una)

| Paquete | Motivo |
|---|---|
| `@nestjs/core`, `@nestjs/common`, `@nestjs/platform-fastify` | Framework pedido; Fastify por menor overhead que Express en el endpoint de decisión |
| `reflect-metadata`, `rxjs` | Dependencias obligatorias de Nest |
| `ioredis` | Cliente Redis mantenido, con `defineCommand` (EVALSHA automático), pipelines, timeouts y backoff |
| `ipaddr.js` | Parsing IPv4/IPv6/CIDR robusto (lo usa también Express); sin dependencias |
| `yaml` | Reglas y sitios en YAML legible; sin dependencias |
| `@prometheus-io/client` | Métricas Prometheus estándar (histogramas correctos). Es el antiguo `prom-client`, ahora mantenido por el proyecto Prometheus; misma API. Exige Node ≥ 22 |

No se usan: class-validator/class-transformer ni clases DTO (la validación son decoradores propios, ver §10), dotenv (systemd `EnvironmentFile=`), axios (fetch nativo), `@nestjs/config`,
`@nestjs/schedule`, `@nestjs/throttler`, helmet (la API es local; el dashboard pone sus cabeceras
de seguridad y CSP con nonce a mano), ORMs ni SQL.

## 4. Instalación rápida

```bash
sudo ./scripts/install.sh --dry-run
sudo ./scripts/install.sh
```

Procedimiento completo y verificaciones: [docs/02-PROCEDIMIENTOS.md](docs/02-PROCEDIMIENTOS.md).
El instalador **no modifica vhosts** y deja todo en **AUDIT**.

## 5. Configuración

### 5.1 `/etc/smartguard/smartguard.env`

Ver [.env.example](.env.example) (comentado). Lo más importante:

| Variable | Por defecto | Qué hace |
|---|---|---|
| `AUDIT_MODE` | `true` | Solo registra `WOULD_*`; cambiar en caliente con `smartguard audit off` |
| `ADMIN_ALLOWLIST` / `SERVICE_ALLOWLIST` / `TRUSTED_NETWORKS` | vacío | IPs/CIDR que nunca se banean (y exentas de límites Nginx tras `nginx-sync`) |
| `SCORE_OBSERVE/RATE_LIMIT/RESTRICT/BLOCK` | 20/40/60/80 | Niveles de respuesta |
| `STRONG_EVIDENCE_MIN` | 40 | Evidencia de alta confianza necesaria para banear una IP entera (NAT) |
| `SCORE_DECAY_PER_MINUTE` | 2 | Decaimiento lineal del score |
| `BAN_FIRST…BAN_MAX` | 15m/1h/6h/24h/7d | Escalado por reincidencia |
| `IPV6_PREFIX` | 64 | Agrupación IPv6 para reputación y bans |
| `REDIS_*` | 127.0.0.1:6379 db 0 | Usa una DB distinta a la del object cache de WordPress |
| `ENABLE_NFTABLES` / `ENABLE_CLOUDFLARE` | false | Integraciones opcionales |

### 5.1b Allowlist y desbloqueo

| Valor | Ejemplo | Cómo se comprueba | Dónde aplica |
|---|---|---|---|
| IP / CIDR | `203.0.113.36`, `2001:db8::/48` | en memoria | SmartGuard + Nginx (límites) + nftables |
| Dominio exacto (cliente) | `app.customily.com` | se resuelve a sus IPs cada 10 min | SmartGuard + Nginx/nftables (IPs resueltas en `nginx-sync`) |
| Subdominios (cliente) | `*.customily.com` | FCrDNS (PTR → dominio → A/AAAA = misma IP), solo ante señales sospechosas, cacheado | Solo SmartGuard |
| Host destino | `apicustomizer.orleansembroidery.com`, `*.dev.orleansembroidery.com` | nombre del host de la petición | SmartGuard no puntúa ese sitio |

```bash
sudo smartguard allow 203.0.113.36                 # tu IP (y la desbloquea si estaba baneada)
sudo smartguard allow app.customily.com SERVICE_ALLOWLIST "Customily"
sudo smartguard allow '*.customily.com' SERVICE_ALLOWLIST
sudo smartguard allow-host apicustomizer.orleansembroidery.com "API interna"
sudo smartguard unallow '*.customily.com'
sudo smartguard allowlist
sudo smartguard lookup 203.0.113.36               # ¿en qué lista está? ¿bloqueada?
sudo smartguard nginx-sync                          # exime también de los límites de Nginx
sudo smartguard unban 1.2.3.4                       # ban de IP + huellas + nftables + Cloudflare + reset de score
sudo smartguard unban 1.2.3.4 --keep-score          # solo quita el ban
```

Estáticas en el `.env` (`ADMIN_ALLOWLIST`, `SERVICE_ALLOWLIST`, `TRUSTED_NETWORKS`, `ALLOW_HOSTS`), dinámicas
por CLI/API/dashboard (Redis). Un PTR solo no prueba nada (lo controla el dueño de la IP): por eso
`*.dominio` exige la resolución directa. Para un vhost que no quieres proteger, lo ideal es no incluir
los snippets de SmartGuard en él; `allow-host` sirve cuando comparte configuración.

### 5.2 Reglas (`rules.yaml`, `rules.d/*.yaml`, overrides por sitio)

Reglas declarativas (sin `if` en el código). Ejemplo:

```yaml
- id: env-scan
  name: Intento de leer .env
  target: path            # path | query | uri | ua | method
  pattern: '(?:^|/)\.env(?:\.[\w.-]{1,30})?$'
  score: 25
  severity: high
  confidence: high        # low: solo huella IP+UA · medium: IP sin banear · high: evidencia fuerte
  category: SENSITIVE_FILE
  action: score           # score | block (corta esta petición) | allow (excepción)
  ttl: 86400
```

- Las regex se validan al cargar: sin cuantificadores anidados, sin alternancias dentro de
  grupos con `+`/`*`, sin backreferences, ≤ 600 caracteres, y se prueban con entradas adversariales.
  Una regla insegura hace fallar la recarga y **se mantiene la configuración anterior**.
- Tus reglas propias van en `/etc/smartguard/rules.d/*.yaml` (update.sh no las toca).
- `smartguard rules reload` recarga sin reiniciar.

### 5.3 Sitios (`sites.yaml`)

```yaml
sites:
  orleansembroidery.com:
    aliases: [www.orleansembroidery.com, www1.orleansembroidery.com]
    multisite: true
    woocommerce: true
    xmlrpc: false
    rules:
      disabled: [wp-user-enum-author]
      overrides: { env-scan: { score: 30 } }
      extra: [ ...reglas propias; mismo id = reemplaza la global... ]
```

Hosts no configurados → reglas globales y host registrado como `_unknown` (el `Host` del cliente
nunca se usa como clave interna).

### 5.4 Bots (`bots.yaml`)

- **Verificados por FCrDNS** (Google, Bing, Apple): IP → PTR → dominio oficial → A/AAAA → misma IP.
  Resultado cacheado en memoria y Redis (24 h positivo / 6 h negativo). **Nunca** DNS síncrono: la
  primera petición de un bot se trata como "no verificada" (sin privilegios ni castigo) mientras se
  verifica en segundo plano.
- **Falsos** (UA de Googlebot sin verificación): `fake-bot:google +15`.
- **No verificables por DNS** (DuckDuckBot, Meta/WhatsApp, Customily): sin privilegios en SmartGuard;
  Nginx mantiene su tratamiento actual (whitelist UA / `botzone`). Para servicios con IP fija, usa
  `SERVICE_ALLOWLIST`.
- **No deseados** (Ahrefs, Semrush, MJ12, Baidu, Yandex…): Nginx ya los bloquea; SmartGuard suma
  puntos si llegan por otra vía.

## 6. Nginx

| Archivo | Contexto | Rol |
|---|---|---|
| `conf.d/smartguard.conf` → instalado como `conf.d/smartguard.conf` o, si nginx.conf solo incluye `sites-enabled/*.conf` (CloudPanel), como `sites-enabled/00-smartguard.conf` | http | incluye todo lo de abajo (solo definiciones) |
| `smartguard/cloudflare-realip.conf` | http | `set_real_ip_from` Cloudflare + `real_ip_header CF-Connecting-IP` (generado) |
| `smartguard/cloudflare-geo.conf` | http | `$sg_tcp_from_cloudflare` (generado) |
| `smartguard/maps.conf` | http | clasificación, claves de límites, reglas Nginx nuevas, qué se registra |
| `smartguard/rate-limits.conf` | http | zonas `sg_dynamic`, `sg_login`, `sg_xmlrpc`, `sg_ajax`, `sg_wcajax`, `sg_rest`, `sg_suspicious`, `sg_conn*` (**editable**) |
| `smartguard/mode.conf` · `limits-mode.conf` | http · server | AUDIT/ENFORCE y kill switch (generados por el CLI) |
| `smartguard/allowlist.conf` | http | `$sg_trusted` (generado por `nginx-sync`) |
| `smartguard/log-format.conf` | http | `log_format smartguard_json` sin datos sensibles |
| `smartguard/upstream.conf` | http | `smartguard_backend` con keepalive |
| `smartguard/server.conf` | server | reglas nuevas + `limit_req`/`limit_conn` + log JSON |
| `smartguard/auth.conf` | server | locations internas de `auth_request` con **fail-open** |
| `smartguard/auth-php.conf` | location | `auth_request` (en cada `location` con `fastcgi_pass`) |
| `smartguard/static-log.conf` | location | log de 4xx en estáticos (sustituye `access_log off`) |
| `smartguard/secret.conf` | server | secreto compartido Nginx→SmartGuard (0600) |

Límites (anti-flood, altos a propósito por NAT/HTTP2/móviles):

| Zona | Clave | Rate | Burst |
|---|---|---|---|
| `sg_dynamic` | IP, todo lo no estático | 30 r/s | 300 |
| `sg_login` | IP, `POST wp-login.php` | 10 r/min | 20 |
| `sg_ajax` | IP, `admin-ajax.php` | 20 r/s | 150 |
| `sg_wcajax` | IP, `?wc-ajax=` | 20 r/s | 150 |
| `sg_rest` | IP, `/wp-json/` y `?rest_route=` | 15 r/s | 150 |
| `sg_xmlrpc` | IP, `xmlrpc.php` | 2 r/min | 5 |
| `sg_suspicious` | IP, curl/python-requests/Go/UA vacío | 5 r/s | 50 |
| `sg_conn` / `sg_conn_dynamic` | IP | 128 / 48 simultáneas | — |

**Sobre 429 en `auth_request`:** Nginx `auth_request` solo entiende 2xx/401/403. SmartGuard responde
429 para `RATE_LIMIT` (según la API pedida), pero `auth.conf` lo traduce a **403** al cliente. No se
usa `error_page 403/429` en la `location` PHP porque tu vhost tiene `fastcgi_intercept_errors on` y
reemplazaría los 401/403 legítimos de WordPress (REST, nonces). Los 429 reales los producen los
`limit_req` de Nginx.

## 7. Cloudflare

- **IP real:** `$remote_addr` = visitante **solo** si la IP TCP es de Cloudflare. `CF-Connecting-IP`
  en una conexión directa se ignora. Verificación: docs/02, 13.6 punto 4.
- **nftables nunca recibe IPs de `CF-Connecting-IP`**: solo IPs TCP de conexiones directas, y los
  rangos de Cloudflare están protegidos en su propio set.
- **Rangos:** `scripts/update-cloudflare-ips.sh` (timer semanal) descarga por HTTPS, valida cada CIDR,
  aborta si la lista es sospechosa, escribe de forma atómica, `nginx -t` antes de recargar y actualiza
  nftables en una sola transacción.
- **Origin lock** (solo Cloudflare + tus IPs en 80/443): `scripts/origin-lock.sh check|enable|disable`.
  No activar hasta que `check` pase (todos los dominios proxyados, sin servicios que conecten directo).
- **API opcional:** IP Access Rules (cuenta o zona) solo para reincidentes con score muy alto, con
  deduplicación, máximo de reglas activas, límite por hora y borrado automático al caducar.

## 8. Redis

Todas las claves con prefijo `smartguard:` y **TTL obligatorio** (detalle en
[src/reputation/redis.store.ts](src/reputation/redis.store.ts)):

| Clave | Contenido | TTL |
|---|---|---|
| `ip:{ip}` | score, evidencia fuerte, ventana de hits, first/last seen | 1 h (renovable) |
| `fp:{hash}` | score de la huella IP+UA | 30 min |
| `reasons:{ip}` | últimos 50 motivos | ≥ 24 h |
| `ban:{ip}` · `ban:fp:{hash}` · `auditban:*` | ban JSON | duración del ban |
| `bans` · `auditbans` | índice ZSET (listados sin SCAN/KEYS) | limpiado en cada inserción |
| `recid:{ip}` | reincidencia | 14 d |
| `dns:{bot}|{ip}` | resultado FCrDNS | 24 h / 6 h |
| `stats:{min}` · `hll:ips:{min}` · `top:*:{h}` | estadísticas agregadas | 48 h |
| `events` | stream de eventos | MAXLEN ~20 000 |

Coste por decisión: **1 `EVALSHA`** (lectura pura si la petición no tiene señales: el tráfico normal
no crea claves). Estadísticas agregadas en memoria y volcadas cada 10 s en un pipeline.
Circuit breaker: 5 errores en 10 s → 30 s usando el almacén en memoria; `enableOfflineQueue=false`
y timeout de 60 ms por comando; reconexión con backoff exponencial hasta 30 s.

Recomendado: una DB propia (`REDIS_DB`) o una instancia dedicada con `maxmemory 128mb` +
`maxmemory-policy volatile-lru` (todas las claves de SmartGuard tienen TTL).

## 9. Scoring y decisiones

| Score | Acción |
|---|---|
| 0–19 | ALLOW |
| 20–39 | OBSERVE (permitido, registrado) |
| 40–59 | RATE_LIMIT (60 peticiones dinámicas/min) |
| 60–79 | RESTRICTION (15/min) |
| ≥ 80 **y** evidencia fuerte ≥ 40 | BLOCK + ban de IP (15m → 1h → 6h → 24h → 7d) |
| ≥ 80 solo en la huella | BLOCK de IP+UA 10 min (el resto del NAT no se ve afectado) |

Protección NAT (punto 11): el volumen **nunca** suma puntos en SmartGuard; las señales de baja
confianza solo afectan a la huella IP+User-Agent; las de confianza media pueden limitar pero
**nunca** banear una IP entera; el bonus de escaneo rápido solo cuenta hits de confianza media/alta.

Cada decisión es explicable: `smartguard ip <IP>` o `GET /admin/ip/<IP>` muestra motivos, decay y
acción (ejemplo en docs/02, 14.1).

## 10. Seguridad del propio SmartGuard

- Escucha solo en `127.0.0.1` (arranca con error si `BIND_ADDRESS` no es loopback).
- Todas las rutas rechazan peticiones que no vienen de loopback.
- `/internal/decision` exige el secreto compartido de Nginx (evita que un PHP/SSRF local envenene
  la reputación de IPs). Nginx no reenvía cookies, Authorization ni cuerpo.
- API admin: `Authorization: Bearer ADMIN_TOKEN` (≥ 32 caracteres, comparación en tiempo constante),
  rate limit, body ≤ 16 KB.
- Validación con **decoradores de parámetro** (sin DTOs ni class-validator): `@ValidBody(esquema)`,
  `@ValidQuery(esquema)`, `@IpParam('ip')`, `@AllowValueParam('value')` en
  [src/common/validation.ts](src/common/validation.ts). Los esquemas son objetos planos
  ([src/admin/admin.schemas.ts](src/admin/admin.schemas.ts)); campos no declarados → 400.
- systemd: usuario `smartguard`, sin capacidades (solo `CAP_NET_ADMIN` con el drop-in de nftables),
  `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, filtro de syscalls, `MemoryMax`.
- nftables sin shell: `execFile("/usr/sbin/nft", argv)` con IP canónica validada por lista blanca.
- Logs sin cookies/tokens/Authorization; queries redactadas; el log de Nginx no guarda query strings.

## 11. Fail-open

| Fallo | Resultado |
|---|---|
| SmartGuard parado / no escucha | `auth_request` → 502 → `@smartguard_failopen` (204) → PHP normal |
| SmartGuard lento (> 300 ms) | 504 → fail-open |
| Error interno en la decisión | SmartGuard responde 200 `ERROR_FAIL_OPEN` |
| Redis caído | Decisiones con almacén en memoria local (reglas y bans locales siguen) |
| Emergencia | `smartguard killswitch on` (Nginx deja de consultar) |

Las reglas puramente Nginx (bots, rutas prohibidas, límites) siguen activas en todos los casos.

## 12. CLI

```
sudo smartguard status | ip <IP> | ban <IP> [1h] [motivo] | unban <IP> | allow <IP/CIDR> [tipo]
               unallow <IP/CIDR> | bans [--audit] | events [N] | report | rules reload
               audit on|off|status | killswitch on|off | nginx-sync | nginx-enable | fw-sync | logs
```

## 13. API local

| Método | Ruta | Auth |
|---|---|---|
| GET | `/internal/decision` | secreto Nginx |
| GET | `/health` · `/ready` · `/metrics` | loopback |
| GET | `/admin/bans?audit=&offset=&limit=` | token |
| GET | `/admin/ip/:ip` | token |
| POST | `/admin/ban` `{ip, duration?, reason?, firewall?, cloudflare?}` | token |
| DELETE | `/admin/ban/:ip` (`?reset=false` conserva el score) | token |
| GET | `/admin/lookup?value=` IP/CIDR/dominio/*.dominio/URL → listas donde está, ban, would-ban, score | token |
| GET | `/admin/allow` (estática, dinámica, dominios resueltos) | token |
| POST | `/admin/allow` `{value, type?, target?: client|host, note?, ttl?, unban?}` | token |
| DELETE | `/admin/allow/:value` | token |
| GET | `/admin/ipinfo?ips=a,b,c` (hasta 50) → red/ASN, organización, país de registro, ¿hosting? | token |
| GET | `/admin/blocked-networks` (redes completas bloqueadas) | token |
| POST | `/admin/blocked-networks` `{ip? | asn?, note?}` — bloquea todos los rangos del ASN | token |
| DELETE | `/admin/blocked-networks?asn=` | token |
| GET | `/admin/blocked-bots` (bots bloqueados por nombre) | token |
| POST | `/admin/blocked-bots` `{pattern, note?, ttl?}` — texto a buscar en el User-Agent | token |
| DELETE | `/admin/blocked-bots?pattern=` | token |
| GET | `/admin/stats?minutes=` · `/admin/events?limit=&from=&to=&ip=` (rango en ms e IP: busca en todos los eventos guardados) · `/admin/events/page?limit=&cursor=&kind=&q=&from=&to=` (paginado por cursor; lo usa el panel) · `/admin/rules` | token |
| POST | `/admin/rules/reload` | token |
| GET/POST | `/admin/mode` `{audit}` | token |
| GET | `/dashboard/` | loopback (datos con token) |

**Errores con código** (el dashboard los traduce): `{ statusCode, code, message, params }`.

| code | Cuándo | params |
|---|---|---|
| `ALREADY_ALLOWLISTED` (409) | el valor ya está en la lista blanca | `matches[]`: lista, valor, origen (.env / dashboard / integrada) |
| `ALREADY_COVERED` (409) | ya lo cubre un rango o `*.dominio` existente | `matches[]` |
| `IP_ALLOWLISTED` (409) | se intenta bloquear una IP de la lista blanca | `matches[]` |
| `ALREADY_BANNED` (409) | la IP ya está bloqueada | `ban` (hasta cuándo, motivo) |
| `CLOUDFLARE_IP` (400) | se intenta bloquear una IP de Cloudflare | `ip` |
| `STATIC_ENTRY` (409) | se intenta quitar una entrada del .env desde la API | `lists` |
| `NOT_IN_ALLOWLIST` (404) · `INVALID_IP` · `INVALID_VALUE` · `HOST_REQUIRES_DOMAIN` · `VALIDATION` (400) | — | `field`, `reason` |

## 13b. Dashboard (Angular, English / Español)

- **Angular 22** standalone + signals, sin zone.js ni librerías de UI (≈56 KB comprimido).
- **Idioma por defecto: inglés**; selector English/Español en la cabecera (se recuerda en el navegador).
  Todos los mensajes, incluidos los errores del backend, se traducen por su `code`.
- Pestañas: **Overview · IPs & sites · Blocked · Allowlist · Events**.
- En **IPs & sites**:
  - *Check*: escribes una IP, CIDR, dominio, `*.dominio` o URL y te dice al momento si **ya está en
    una lista y en cuál** (Admin IPs / Services / Trusted networks / Exempt sites, origen .env o
    dashboard, y por qué coincide: exacta, dentro de un rango, IP de un dominio…), si está bloqueada
    y hasta cuándo, y su score.
  - *Allow a client*: IP / CIDR / dominio / `*.dominio` en la lista elegida (permitir una IP la desbloquea).
  - *Allow a site or subdomain*: dominio, `*.dominio` o URL (`https://api.ejemplo.com/ruta` → `api.ejemplo.com`).
  - *Block an IP* (15 min … 1 año) y *Unblock an IP* (con opción de conservar el score).
  - Si el valor ya estaba, se muestra el aviso con la lista (el backend lo valida también: 409).
- En **Events**, cada fila tiene *Block IP* (24 h) y *Block bot* (por nombre: propone el nombre propio
  del bot a partir del User-Agent). La lista de bots bloqueados se gestiona en **Blocked**.
- *Block network* (en Events y Overview) bloquea **la red entera** de esa IP: todos los rangos que anuncia
  su ASN (p. ej. los ~900 de DigitalOcean), descargados de RIPEstat y refrescados cada día. La pertenencia
  se comprueba en memoria por búsqueda binaria, sin I/O en la decisión. Cloudflare no se puede bloquear.
  Pensado para proveedores de hosting; en una operadora de internet bloquearía a clientes reales.
- Los bloqueos manuales de IP, bot y red **no caducan**: duran hasta que se desbloquean en **Blocked**.
- **Los bloqueos manuales (IP, bot o red) se aplican siempre, también en AUDIT**: AUDIT solo deja en
  suspenso lo que SmartGuard decide por su cuenta. Nunca bloquean IPs de la lista blanca ni buscadores
  verificados, y se rechazan los textos que también cubren navegadores reales (`chrome`, `mozilla`…).
  Actúan sobre lo que va a PHP (auth_request); los archivos estáticos no pasan por SmartGuard.
- Bajo cada IP se muestra **a quién pertenece**: país y organización de la red (p. ej. `US · DigitalOcean, LLC`)
  y la etiqueta *data center* si es un proveedor de hosting (servidores, no personas). Fuente: IP→ASN de
  Team Cymru por DNS, con caché de 24 h; solo se consulta al abrir una tabla, nunca al decidir. El país
  es el de **registro de la red**, no geolocalización exacta. La columna *Country* usa `CF-IPCountry` cuando
  llega (Cloudflare → Network → IP Geolocation) y, si no, ese país de registro.
- Seguridad: solo loopback, token en `sessionStorage`, CSP `script-src 'self'` y estilos con nonce
  por petición, sin inline scripts.

Acceso: `ssh -L 3100:127.0.0.1:3100 usuario@vps` y abrir `http://127.0.0.1:3100/dashboard/`.

Compilar: `npm run build:dashboard` (o `cd dashboard && npm ci && npx ng build`). `install.sh`/`update.sh`
usan el build incluido en `dashboard/dist/browser` o lo compilan. Desarrollo:
`cd dashboard && npx ng serve --proxy-config proxy.conf.json` (con SmartGuard en 127.0.0.1:3100).

## 14. Tests

```bash
npm ci
npm test                         # unitarios + integración HTTP (sin Redis)
# Lua contra Redis real (en el servidor, DB de pruebas):
SMARTGUARD_TEST_REDIS=1 REDIS_DB=15 npx jest tests/integration/redis-lua
```

Cubre: visitante normal, NAT 500 peticiones, WooCommerce `wc-ajax`, `admin-ajax`, Multisite
`/site1/wp-admin/`, scanner (.env/.git/shell/phpinfo/phpunit), reincidencia, AUDIT, IPv6 /64,
huella vs IP (NAT), Googlebot falso (incl. PTR falsificado), Googlebot real (IPv4/IPv6), allowlist,
`action: block`, decay, Redis caído (fail-open), credential stuffing, logins exitosos, doble conteo
analizador/decisión, enumeración de plugins, anti-ReDoS, todas las reglas del repo contra rutas
legítimas, API admin, validación por decoradores, allowlist por dominio/subdominio/host, desbloqueo completo, cambio de modo en caliente y CSP del dashboard.

Pruebas en el servidor: `scripts/test-attacks.sh` (seguro, IPs de documentación) y
`scripts/loadtest.sh` (baseline vs SmartGuard).

## 15. Troubleshooting

| Síntoma | Comprobar |
|---|---|
| `nginx -t` falla tras instalar | `nginx -T | grep -n smartguard`; ¿realip duplicado? → reinstalar con `--skip-realip` |
| Todo el tráfico sale con la IP de Cloudflare | realip no activo: `nginx -T | grep real_ip` |
| `x-smartguard-decision: UNAUTHENTICATED` en logs | `sudo smartguard nginx-sync` (secreto desincronizado) |
| SmartGuard no arranca | `journalctl -u smartguard -n 80 --no-pager` (ADMIN_TOKEN corto, YAML inválido, Node en /home) |
| Dashboard/CLI 401 | `ADMIN_TOKEN` del .env; CLI con `sudo` |
| `degraded: true` | Redis caído o `REDIS_PASSWORD`/`REDIS_DB` incorrectos |
| Un cliente legítimo bloqueado | `sudo smartguard ip <IP>` → `unban` → allowlist o ajustar regla |
| Analizador sin datos | `ls -l /var/log/nginx/smartguard/`; `id smartguard` (grupo adm) |

## 16. Rollback, actualización y desinstalación

```bash
sudo /opt/smartguard/scripts/rollback-nginx.sh --disable      # neutraliza SmartGuard en Nginx (reversible)
sudo smartguard nginx-enable                                  # deshace lo anterior
sudo /opt/smartguard/scripts/rollback-nginx.sh --list
sudo /opt/smartguard/scripts/rollback-nginx.sh --restore /etc/nginx/backups/nginx-….tar.gz
cd nueva-version && sudo ./scripts/update.sh                  # conserva .env, reglas, sitios, allowlists
sudo /opt/smartguard/scripts/update.sh --revert
sudo /opt/smartguard/scripts/uninstall.sh [--purge]
```

## 17. Roadmap

- **V1 (este repositorio):** hardening Nginx, IP real Cloudflare, Redis, scoring + reglas,
  AUDIT/ENFORCE, bans con reincidencia, analizador de logs, `auth_request` fail-open, systemd, CLI,
  tests. Incluidos también (seguros y opcionales): nftables, origin-lock, API Cloudflare, dashboard,
  métricas Prometheus, alertas por webhook.
- **V2:** Unix socket para la API; geo de Nginx con rangos oficiales de Googlebot/Bingbot
  (googlebot.json, bingbot.json) para verificar sin DNS; mu-plugin opcional de WordPress que informe
  de logins fallidos (hash del usuario, sin contraseñas) para detectar "muchos usernames"; alertas
  Telegram/email; histórico opcional en PostgreSQL (asíncrono, fuera del camino crítico).
- **V3:** detección estadística (líneas base por endpoint/hora, anomalías por sitio), interfaz para
  modelos ML fuera del camino crítico.

## 18. Limitaciones conocidas (honestas)

- La configuración Nginx y los scripts bash **no se han ejecutado en un servidor real** en este
  entorno de desarrollo (Windows): `bash -n` y shellcheck pasan, y el instalador valida todo con
  `nginx -t` antes de recargar y revierte si falla. Ejecuta primero `install.sh --dry-run`.
- El script Lua se verificó en una VM Lua con un `redis.call` simulado frente a la implementación en
  memoria (resultados idénticos). Confírmalo en el servidor con el test `redis-lua` (sección 14).
- `RATE_LIMIT` de SmartGuard llega al cliente como 403 (limitación de `auth_request`, ver sección 6).
- Sin el cuerpo de las peticiones (privacidad) no se cuentan usernames distintos en wp-login; se
  detecta credential stuffing por volumen de logins fallidos (POST 200) por IP y por huella.
- GeoIP: solo como contexto a partir de `CF-IPCountry` cuando la conexión viene de Cloudflare; no se
  bloquean países.
- Si la cabecera `CF-IPCountry` no llega (sitio sin proxy), no hay país.
