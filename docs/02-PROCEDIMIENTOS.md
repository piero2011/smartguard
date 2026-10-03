# Procedimientos: instalación (FASE 13), AUDIT (FASE 14) y ENFORCEMENT (FASE 15)

Todos los comandos se ejecutan en el VPS como un usuario con `sudo`. Donde pone
`orleansembroidery.com`, sustituye por el dominio que estés probando.

---

## FASE 13 — Instalación exacta en Debian 13

### 13.1 Preparación (sin cambios en el tráfico)

```bash
# Paquetes base (nodejs de Debian 13 es 20.x; si ya tienes Node ≥ 20 del sistema, sáltalo)
sudo apt-get update
sudo apt-get install -y nodejs npm curl openssl tar rsync nftables redis-tools

# Node debe estar en /usr/bin (NO nvm en /home: systemd usa ProtectHome)
command -v node && node -v            # ≥ v20.11

# Nginx con los módulos necesarios
sudo nginx -V 2>&1 | tr ' ' '\n' | grep -E 'auth_request|realip'
sudo nginx -t

# ¿Ya existe real_ip? (si aparece algo, el instalador NO duplica)
sudo nginx -T 2>/dev/null | grep -nE 'real_ip_header|set_real_ip_from'

# ¿Qué incluye nginx.conf dentro de http {}? En tu CloudPanel solo sites-enabled/*.conf →
# el instalador pondrá el contexto http en /etc/nginx/sites-enabled/00-smartguard.conf
sudo nginx -T 2>/dev/null | grep -nE 'include .*(conf\.d|sites-enabled)'

# Redis
redis-cli ping
```

### 13.2 Copiar el proyecto al servidor

Desde tu PC (la carpeta `smartguard/` de este repositorio):

```bash
scp -r smartguard/ usuario@TU_VPS:/tmp/smartguard-src
# o: rsync -av --exclude node_modules --exclude dist smartguard/ usuario@TU_VPS:/tmp/smartguard-src/
```

### 13.3 Simulación y instalación

```bash
cd /tmp/smartguard-src
sudo ./scripts/install.sh --dry-run          # muestra TODO lo que haría, sin escribir nada
sudo ./scripts/install.sh                    # instala (pide confirmación)
# Con firewall nftables (tabla propia, sin policy drop, sin origin-lock):
# sudo ./scripts/install.sh --enable-nftables
```

Resultado: SmartGuard corriendo en `127.0.0.1:3100`, **AUDIT_MODE=true**, reglas Nginx nuevas en
AUDIT, backup en `/etc/nginx/backups/nginx-<fecha>-pre-install.tar.gz`.

### 13.4 Configuración mínima

```bash
sudo nano /etc/smartguard/smartguard.env
#   ADMIN_ALLOWLIST=203.0.113.36/32          ← tu(s) IP(s) de administración
#   SERVICE_ALLOWLIST=                         ← IPs, dominios (app.x.com) o subdominios (*.x.com) de servicios
#   ALLOW_HOSTS=                               ← tus subdominios/APIs que SmartGuard no debe puntuar
#   REDIS_DB=5                                 ← una DB distinta a la del object cache de WP
#   REDIS_PASSWORD=...                         ← si tu Redis tiene contraseña

sudo nano /etc/smartguard/sites.yaml          # tus dominios, multisite, woocommerce, xmlrpc

sudo smartguard nginx-sync                     # allowlist → Nginx (exentas de límites) + secreto
sudo systemctl restart smartguard
sudo smartguard status
```

### 13.5 Activar en el vhost (CloudPanel)

1. CloudPanel → **Sites** → `orleansembroidery.com` → **Vhost**.
2. Copia tu vhost actual a un archivo local (segunda copia de seguridad).
3. Añade a tu vhost los `include` de SmartGuard (bloque de abajo).
4. **Save**. CloudPanel ejecuta `nginx -t`; si falla no aplica nada.

Para otros WordPress del VPS (vhosts independientes), añade SOLO esto a su vhost:

```nginx
server {
    ...
    index index.php index.html;

    include /etc/nginx/smartguard/server.conf;   # ← al principio del server
    include /etc/nginx/smartguard/auth.conf;
    ...
    location ~ \.php$ {
        include /etc/nginx/smartguard/auth-php.conf;   # ← en CADA location con fastcgi_pass
        ...
    }
}
```

Y en la location de estáticos, cambia `access_log off;` por
`include /etc/nginx/smartguard/static-log.conf;` (opcional, recomendado).

### 13.6 Verificaciones inmediatas

```bash
# 1. La web funciona
curl -sI https://orleansembroidery.com/ | head -1
curl -sI https://orleansembroidery.com/wp-login.php | head -1
curl -sI "https://orleansembroidery.com/?wc-ajax=get_refreshed_fragments" | head -1

# 2. SmartGuard recibe decisiones (deben crecer)
sudo smartguard status

# 3. IP real con Cloudflare: haz una visita desde tu navegador y mira el log
sudo tail -n 5 /var/log/nginx/smartguard/access.json
#    "ip" = TU IP pública · "tcp" = IP de Cloudflare · "cf":1

# 4. Anti-spoofing: petición DIRECTA al origen falsificando CF-Connecting-IP
curl -sk -o /dev/null -H 'Host: orleansembroidery.com' -H 'CF-Connecting-IP: 1.2.3.4' \
     "https://IP_DEL_VPS/.env"
sudo tail -n 1 /var/log/nginx/smartguard/access.json
#    "ip" debe ser TU IP (no 1.2.3.4) y "cf":0  → el header falso se ignora ✔

# 5. Estáticos NO consultan a SmartGuard: esta petición no debe cambiar el contador de decisiones
curl -s -o /dev/null https://orleansembroidery.com/wp-includes/css/dist/block-library/style.min.css

# 6. Fail-open: con SmartGuard parado la tienda sigue funcionando
sudo systemctl stop smartguard
curl -sI https://orleansembroidery.com/ | head -1          # 200
curl -sI https://orleansembroidery.com/cart/ | head -1     # 200
sudo systemctl start smartguard

# 7. Redis caído (sin tocar tu Redis real, que puede usar WordPress)
sudo sed -i 's/^REDIS_PORT=.*/REDIS_PORT=1/' /etc/smartguard/smartguard.env && sudo systemctl restart smartguard
sudo smartguard status        # redis:false, degraded:true — y la web sigue igual
sudo sed -i 's/^REDIS_PORT=.*/REDIS_PORT=6379/' /etc/smartguard/smartguard.env && sudo systemctl restart smartguard

# 8. Multisite
curl -sI https://orleansembroidery.com/SUBSITIO/wp-admin/ | head -1   # 302 al login (normal)
curl -sI https://orleansembroidery.com/SUBSITIO/wp-content/uploads/ALGUNA-IMAGEN.jpg | head -1

# 9. Let's Encrypt
curl -s -o /dev/null -w '%{http_code}\n' http://orleansembroidery.com/.well-known/acme-challenge/test   # 404 (no 403)
```

---

## FASE 14 — Procedimiento de prueba en AUDIT MODE (24–72 h)

En AUDIT **nada nuevo se bloquea**: SmartGuard responde siempre 200 (etiqueta `WOULD_*`), los
`limit_req` nuevos van en `dry_run`, y las reglas Nginx nuevas solo se registran (`"nb"` en el log).
Tus reglas de siempre (bots, `.git`, archivos ocultos, xmlrpc 444…) siguen actuando como hoy.

### 14.1 Día 0: pruebas controladas

```bash
# Ataques simulados contra la API local con IPs de documentación (no afecta a nadie real)
sudo /opt/smartguard/scripts/test-attacks.sh
# Esperado: navegación normal = 200 ALLOW; scanner → WOULD_BLOCK en ≤ 3-4 peticiones;
#           payloads → WOULD_BLOCK/OBSERVE; IPv6 /64 completo → WOULD_BLOCK.

# Explicación de una IP
sudo smartguard ip 198.51.100.77
```

Ejemplo de salida:

```
IP: 198.51.100.77
Score: 145  (evidencia fuerte: 145)

Reasons:
  phpunit-rce +50
  webshell-scan +40
  env-scan +25
  git-scan +25
  rapid_scanning +20
  phpinfo-probe +15
  decay -0.3

Action:
  ALLOW
  (AUDIT: se habría baneado 15m por: env-scan+25, git-scan+25, webshell-scan+40)
```

### 14.2 Días 1–3: revisión diaria (10 minutos)

```bash
sudo smartguard report             # resumen de lo que se HABRÍA bloqueado + posibles falsos positivos
sudo smartguard bans --audit       # would-bans (¿alguna IP conocida? ¿tu oficina? ¿un servicio?)
sudo smartguard events 50
sudo journalctl -u smartguard --since "24 hours ago" | grep -E 'WOULD_BLOCK|WOULD_RATE_LIMIT' | tail -n 50
```

Qué buscar y cómo corregir:

| Hallazgo | Acción |
|---|---|
| Una IP tuya / de tu equipo en would-bans | `ADMIN_ALLOWLIST` o `TRUSTED_NETWORKS` + `smartguard nginx-sync` |
| Un servicio (Customily, pasarela, tu panel) con 429 dry-run o would-block | `SERVICE_ALLOWLIST` + `smartguard nginx-sync` |
| `nb` con una ruta legítima (p. ej. un subsitio `/console/`) | Quitar esa ruta de `$sg_block_path` en `/etc/nginx/smartguard/maps.conf` |
| Una regla de SmartGuard dispara en tráfico legítimo | Override en `sites.yaml` (`score`, `enabled: false`) o regla `action: allow` en `rules.d/` → `smartguard rules reload` |
| `GuzzleHttp` 403 de una integración real | Quita `"~*guzzlehttp"` de `$is_blocked_bot` en el vhost (decisión tuya) |
| Muchas IPs con 429 dry-run en `sg_dynamic` (tráfico real alto) | Sube `rate`/`burst` en `rate-limits.conf` / `server.conf` |

Métricas de confianza para pasar a ENFORCE:

- `would-bans` = solo IPs de scanners evidentes (`.env`, webshells, phpunit…).
- 0 falsos positivos con IPs de clientes reales / tu equipo / servicios.
- `report` no muestra rutas legítimas en `nb`.
- Ningún 429 dry-run para IPs conocidas.

---

## FASE 15 — Activar ENFORCEMENT (sin reinstalar)

```bash
sudo smartguard audit off
```

Esto, en una sola operación:

1. `POST /admin/mode {"audit":false}` → SmartGuard empieza a responder 403/429 (todas las instancias).
2. `AUDIT_MODE=false` en `/etc/smartguard/smartguard.env` (persistente tras reinicios).
3. `mode.conf` → `$sg_nginx_enforce 1` (reglas Nginx nuevas bloquean con 403).
4. `limits-mode.conf` → `limit_req_dry_run off` (los límites devuelven 429).
5. `nginx -t && systemctl reload nginx` (si `-t` falla, se restaura el modo anterior).

### 15.1 Verificación tras activar

```bash
sudo smartguard status
sudo /opt/smartguard/scripts/test-attacks.sh          # ahora: 403 BLOCK en vez de WOULD_BLOCK
curl -sI https://orleansembroidery.com/ | head -1      # 200
curl -sI https://orleansembroidery.com/checkout/ | head -1
curl -s -o /dev/null -w '%{http_code}\n' https://orleansembroidery.com/phpmyadmin/   # 403 (Nginx, sin PHP)
curl -s -o /dev/null -w '%{http_code}\n' https://orleansembroidery.com/backup.sql    # 403 (Nginx, sin PHP)
```

Vigila las primeras horas: `sudo smartguard events 50` y `sudo smartguard bans`.

### 15.2 Marcha atrás inmediata

```bash
sudo smartguard audit on                 # vuelve a AUDIT (segundos, sin reinstalar)
sudo smartguard killswitch on            # Nginx deja de consultar a SmartGuard (emergencia)
sudo smartguard unban 1.2.3.4            # desbanear a alguien concreto
sudo /opt/smartguard/scripts/rollback-nginx.sh --disable   # neutralizar SmartGuard en Nginx
```

### 15.3 Opcionales tras 1–2 semanas estables

```bash
# nftables (si no lo instalaste): tabla propia, bans solo para IPs TCP directas (no Cloudflare)
sudo /tmp/smartguard-src/scripts/install.sh --enable-nftables   # re-ejecutar instalador (conserva config)

# Bloqueo del origen (solo Cloudflare + tus IPs en 80/443)
sudo /opt/smartguard/scripts/origin-lock.sh check
sudo /opt/smartguard/scripts/origin-lock.sh enable --dry-run
sudo /opt/smartguard/scripts/origin-lock.sh enable

# Cloudflare API (reincidentes con evidencia muy fuerte)
sudo nano /etc/smartguard/smartguard.env   # ENABLE_CLOUDFLARE=true, CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
sudo systemctl restart smartguard
```

### 15.4 Load test (fuera de horas punta)

```bash
sudo apt-get install -y wrk            # u oha/hey
sudo /opt/smartguard/scripts/loadtest.sh decision --duration 30s --concurrency 50
sudo /opt/smartguard/scripts/loadtest.sh e2e --host orleansembroidery.com --path '/?sg_bench=1' --duration 30s --concurrency 20
```

Objetivo: SmartGuard añade < 1–2 ms de p99 y < 5 % de diferencia en req/s frente al baseline.
