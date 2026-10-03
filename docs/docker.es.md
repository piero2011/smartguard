# SmartGuard con Docker y Docker Compose

[English](docker.md) · **Español**

Esta guía ejecuta SmartGuard en contenedores: un **Nginx** con las reglas de SmartGuard, el servicio
de decisión **SmartGuard** con su panel y **Redis**, todo delante de tu aplicación.

> **Estado.** Estos archivos se escribieron y revisaron sin un motor de Docker disponible. El script
> de arranque del contenedor y el servicio se probaron por separado, pero la pila completa aún no se
> ha levantado con `docker compose up`. Sigue la [lista de comprobación](#8-lista-de-comprobación-tras-el-primer-arranque)
> la primera vez y empieza en modo AUDIT (el valor por defecto), que no bloquea nada.

## 1. Qué incluye

```
Internet ──► nginx (puerto 80) ──► tu aplicación (WordPress, …)
               │  ▲
   auth_request│  │permitir / bloquear
               ▼  │
            smartguard ──► redis
          (panel en 127.0.0.1:3100)
```

| Servicio | Imagen | Función |
|---|---|---|
| `nginx` | construida con `docker/nginx/Dockerfile` (`nginx:stable` oficial + fragmentos de SmartGuard) | Recibe el tráfico, aplica las reglas y límites de Nginx y consulta a SmartGuard antes de pasar una petición a la aplicación |
| `smartguard` | construida con `Dockerfile` | Servicio de decisión, analizador de logs, API de administración y panel |
| `redis` | `redis:7-alpine` | Reputación, bloqueos, listas y estadísticas |
| `wordpress` + `db` | `wordpress:6-apache`, `mariadb:11` | **Solo demostración** (perfil `demo`): una aplicación para probar la pila |

Volúmenes: `redis_data`, `smartguard_data` (reglas del panel, estado del analizador), `nginx_logs`
(log de seguridad compartido entre Nginx y SmartGuard) y `nginx_conf` (configuración generada del sitio).

## 2. Requisitos

- Docker Engine 24 o posterior con el plugin Compose (`docker compose version`).
- Servidor Linux. En Docker Desktop (Windows/macOS) la pila funciona, pero Nginx no ve la IP real de
  los visitantes, así que úsalo solo para probar.
- El puerto 80 libre en el servidor (o cambia `HTTP_PORT`).

## 3. Inicio rápido

```bash
git clone https://github.com/piero2011/smartguard.git
cd smartguard
cp docker/env.example .env
```

Edita `.env` y pon los dos secretos (genera cada uno con `openssl rand -hex 32`):

```
ADMIN_TOKEN=…                  # para abrir el panel
DECISION_SHARED_SECRET=…       # compartido entre Nginx y SmartGuard
```

Después arráncalo. Para probarlo con el WordPress de demostración:

```bash
docker compose --profile demo up -d --build
```

Abre `http://localhost/` (aparece el instalador de WordPress) y el panel en
`http://127.0.0.1:3100/dashboard/`, con el `ADMIN_TOKEN` como token de acceso.

Para ponerlo delante de **tu propia aplicación**, define esto en `.env` y arranca sin el perfil de
demostración:

```
SERVER_NAME=tienda.com www.tienda.com
APP_UPSTREAM=http://mi-app:8080
```

```bash
docker compose up -d --build
```

## 4. Conectar tu aplicación

`APP_UPSTREAM` es adonde Nginx envía las peticiones que SmartGuard permite. La dirección debe ser
alcanzable desde el contenedor `nginx`:

| Tu aplicación corre… | `APP_UPSTREAM` |
|---|---|
| como un servicio que añades a este `docker-compose.yml` (misma red) | `http://nombre-del-servicio:puerto` |
| en otro proyecto de Compose | conéctala a la red `smartguard_smartguard` (`docker network connect`) y usa `http://nombre-del-contenedor:puerto` |
| en el propio servidor de Docker | `http://172.30.77.1:puerto` (la puerta de enlace de la red de Compose es el servidor; la aplicación debe escuchar en esa dirección o en `0.0.0.0`) |
| en otra máquina | `http://10.0.0.5:8080` |

La definición del sitio es `docker/nginx/templates/site.conf.template`. Envía todo a través de
SmartGuard salvo los archivos estáticos (imágenes, CSS, JS, fuentes). Para cambiarla — varios sitios,
otros tipos de estáticos, tus propias cabeceras — edita ese archivo y reconstruye
(`docker compose up -d --build nginx`), o monta tu propio archivo sobre
`/etc/nginx/templates/site.conf.template`.

**HTTPS.** La pila escucha en HTTP (puerto 80). Ponla detrás de algo que termine TLS: Cloudflare, un
balanceador o un proxy inverso en el servidor. La cabecera `X-Forwarded-Proto` de ese proxy se pasa a
la aplicación. Para terminar TLS en este mismo Nginx, añade a la plantilla un `server` con
`listen 443 ssl` y tus certificados, y publica el puerto 443.

**IP real del visitante.** Detrás de Cloudflare, la IP real se toma de `CF-Connecting-IP` (solo cuando
la conexión viene de verdad de Cloudflare). Detrás de otro proxy, añade su dirección con
`set_real_ip_from` y `real_ip_header` en la plantilla; si no, todos los visitantes compartirían la IP
del proxy y SmartGuard los puntuaría como uno solo.

## 5. Configuración

Todo se define en `.env` (ver `docker/env.example`):

| Variable | Por defecto | Qué hace |
|---|---|---|
| `ADMIN_TOKEN` | — (obligatoria) | Token del panel y de la API de administración, al menos 32 caracteres |
| `DECISION_SHARED_SECRET` | — (obligatoria) | Secreto entre Nginx y SmartGuard, 24–128 letras y dígitos |
| `SERVER_NAME` | `_` | Dominios que atiende Nginx |
| `APP_UPSTREAM` | `http://wordpress:80` | Tu aplicación |
| `HTTP_PORT` | `80` | Puerto publicado para el sitio |
| `DASHBOARD_PORT` | `3100` | Puerto del panel, publicado solo en `127.0.0.1` |
| `AUDIT_MODE` | `true` | `true` solo registra; `false` bloquea |
| `ADMIN_ALLOWLIST`, `SERVICE_ALLOWLIST`, `TRUSTED_NETWORKS` | vacío | IPs, CIDRs o dominios que nunca se bloquean |
| `ALLOW_HOSTS` | vacío | Hosts destino que SmartGuard no puntúa |

Cualquier otra variable de [.env.example](../.env.example) (umbrales de puntuación, duración de los
bloqueos, API de Cloudflare…) también se puede añadir a `.env`; se pasa al servicio `smartguard`.

**Tus propias reglas, sitios y bots.** Pon `rules.yaml`, `sites.yaml`, `bots.yaml` o `rules.d/*.yaml`
en `docker/config/` y reinicia el servicio (`docker compose restart smartguard`). Los archivos que no
estén ahí usan los valores por defecto de la imagen. Las reglas también se pueden crear desde el panel
(pestaña **Reglas**); esas viven en el volumen `smartguard_data`.

**De AUDIT a ENFORCE.** Tras un día o más en AUDIT, revisa las pestañas **Resumen**, **Eventos** y
**Tráfico**. Cuando no se esté señalando nada legítimo, pon `AUDIT_MODE=false` en `.env` y ejecuta
`docker compose up -d`. Eso recrea los dos contenedores para que Nginx y SmartGuard cambien a la vez.
El botón de la cabecera del panel solo cambia las decisiones propias de SmartGuard y se recuerda en
Redis; si lo usaste, comprueba que la etiqueta de la cabecera muestra el modo que esperas.

## 6. Día a día

```bash
docker compose ps                         # estado de los servicios
docker compose logs -f smartguard         # registro de SmartGuard
docker compose logs -f nginx              # registro de Nginx
docker compose restart smartguard         # tras cambiar docker/config
docker compose up -d                      # tras cambiar .env
docker compose down                       # parar (los volúmenes se conservan)
```

Actualizar a una versión nueva:

```bash
git pull
docker compose up -d --build
```

Copia de seguridad de lo que gestiona el panel (reglas, lista blanca, bloqueos manuales, bots, redes):
desde la pestaña **Copia**, que descarga un archivo importable en otro SmartGuard. Para una copia
completa guarda además `.env`, `docker/config/` y los volúmenes `smartguard_data` y `redis_data`.

## 7. Diferencias con la instalación en servidor

El comando `smartguard` de la instalación en servidor gestiona systemd y el Nginx del servidor, así
que no está disponible en los contenedores. En su lugar:

| En un servidor | Con Docker |
|---|---|
| `smartguard status`, `logs` | `docker compose ps`, `docker compose logs` |
| `smartguard allow`, `ban`, `unban`, `allow-host` | panel (**IPs y sitios**, **Bloqueadas**, **Lista blanca**) o las listas blancas de `.env` |
| `smartguard audit on/off` | `AUDIT_MODE` en `.env` + `docker compose up -d` |
| `smartguard protect <sitio>` | todo sitio de la plantilla de Nginx queda protegido |
| `smartguard update` | `git pull && docker compose up -d --build` |
| `smartguard backup` / `restore` | pestaña **Copia** del panel + volúmenes |
| `smartguard nginx-sync` | automático en cada arranque del contenedor `nginx` |

Tampoco están disponibles en Docker el bloqueo por nftables ni el origin lock (actúan sobre el
firewall del servidor).

La lista blanca añadida desde el panel exime a los clientes de las decisiones de SmartGuard al
momento. La exención de los **límites de peticiones de Nginx** solo cubre las IPs y CIDRs escritos en
`.env`, y se aplica al arrancar el contenedor `nginx`.

## 8. Lista de comprobación tras el primer arranque

1. `docker compose ps` — los tres servicios están `running` y `smartguard` está `healthy`.
2. `curl -I http://localhost/` — tu aplicación responde (200 o una redirección).
3. `curl -s -o /dev/null -w "%{http_code}\n" http://localhost/.env` — en AUDIT SmartGuard no la
   bloquea; unos segundos después la petición aparece en el panel (**Eventos**).
4. El panel abre en `http://127.0.0.1:3100/dashboard/` y acepta el `ADMIN_TOKEN`.
5. En **Tráfico**, la IP que aparece para tu propia visita es tu IP real, no `172.30.77.x`. Si es una
   dirección de contenedor, revisa "IP real del visitante" más arriba.
6. Solo entonces pon `AUDIT_MODE=false`. Repite el paso 3: ahora debe responder `403`.

Si `nginx` no arranca, `docker compose logs nginx` dice por qué; las causas habituales son que falte
`DECISION_SHARED_SECRET` o un error de sintaxis en una plantilla editada.

## 9. Sin Compose (`docker run`)

La misma pila con comandos de Docker:

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

`--env-file .env` da a los dos contenedores los secretos, `SERVER_NAME`, `APP_UPSTREAM` y
`AUDIT_MODE`. Tu aplicación debe estar conectada a la misma red `smartguard` (o ser alcanzable en la
dirección de `APP_UPSTREAM`).

## 10. Notas de seguridad

- El servicio `smartguard` escucha en todas las interfaces **dentro de su contenedor**, pero solo
  acepta conexiones de loopback y de la red de Compose declarada en `LOCAL_NETWORKS`
  (`172.30.77.0/24`). La API de administración exige además el token. Nunca pongas ahí una red pública.
- El puerto del panel se publica solo en `127.0.0.1`. Para llegar desde fuera usa un túnel SSH
  (`ssh -L 3100:127.0.0.1:3100 usuario@servidor`) o pon delante un proxy inverso HTTPS con control de acceso.
- Si cambias la subred en `docker-compose.yml`, cambia `LOCAL_NETWORKS` para que coincida.
- El servicio corre con un usuario sin privilegios y sin ninguna capacidad de Linux.
- La pila no rota el log de seguridad (volumen `nginx_logs`). Solo recibe líneas relevantes para la
  seguridad, así que crece despacio; vacíalo cuando haga falta con
  `docker compose exec nginx sh -c ': > /var/log/nginx/smartguard/access.json'`.
