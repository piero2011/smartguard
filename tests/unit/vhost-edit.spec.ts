import { parseVhost } from '../../src/admin/nginx-sites.service';
import { parseNginx, protectVhost, unprotectVhost } from '../../src/nginx/vhost-edit';

/** WordPress con PHP directo (un solo server{} con contenido + uno que redirige). */
const DIRECT = `server {
  listen 80;
  listen 443 ssl;
  server_name www.shop.test;
  return 301 https://shop.test$request_uri;
}

server {
  listen 80;
  listen 443 ssl;
  server_name shop.test;
  root /home/shop/htdocs;
  index index.php index.html;

  location ~ /\\.git { deny all; }

  # location ~ \\.php$ { fastcgi_pass comentado; }
  location ~ \\.php$ {
    include fastcgi_params;
    fastcgi_param PHP_VALUE "memory_limit=512M; a={b}";
    try_files $uri =404;
    fastcgi_pass 127.0.0.1:17001;
  }

  location / {
    try_files $uri $uri/ /index.php?$args;
  }
}
`;

/** Plantilla de CloudPanel: entrada 80/443 que hace proxy a un backend 8080 con PHP. */
const CLOUDPANEL = `server {
  listen 80;
  listen [::]:80;
  listen 443 quic;
  listen 443 ssl;
  server_name site.test www.site.test;

  location ~ /.well-known {
    auth_basic off;
    allow all;
  }

  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }

  location ~* ^.+\\.(css|js|jpg|png)$ {
    expires max;
    access_log off;
  }
}

server {
  listen 8080;
  listen [::]:8080;
  server_name site.test www.site.test;
  root /home/site/htdocs;
  try_files $uri $uri/ /index.php?$args;

  location ~ \\.php$ {
    include fastcgi_params;
    fastcgi_pass 127.0.0.1:17002;
  }
}
`;

/** Aplicativo Node detrás de proxy. */
const APP = `server {
  listen 443 ssl;
  server_name api.test;
  location / { proxy_pass http://127.0.0.1:3000; }
}
`;

describe('smartguard protect: edición de vhosts', () => {
  it('lee bloques y directivas ignorando comentarios, comillas y ${variables}', () => {
    const root = parseNginx('a 1; # b {\nserver { set $x "${y}{"; location / { return 200 "}"; } }');
    expect(root.directives.map((d) => d.name)).toEqual(['a']);
    expect(root.children).toHaveLength(1);
    expect(root.children[0]!.children[0]!.name).toBe('location');
  });

  it('PHP directo: includes tras server_name y en la location con fastcgi_pass; no toca el redirect', () => {
    const r = protectVhost(DIRECT);
    expect(r).toMatchObject({ rules: true, decision: true, warnings: [] });
    expect(r.changes.map((c) => c.text)).toEqual([
      '+ include /etc/nginx/smartguard/server.conf;',
      '+ include /etc/nginx/smartguard/auth.conf;',
      '+ include /etc/nginx/smartguard/auth-php.conf;',
    ]);
    const lines = r.text.split('\n');
    const name = lines.findIndex((l) => l.includes('server_name shop.test;'));
    expect(lines[name + 1]).toMatch(/^ {2}include \/etc\/nginx\/smartguard\/server\.conf;/);
    expect(lines[name + 2]).toMatch(/^ {2}include \/etc\/nginx\/smartguard\/auth\.conf;/);
    const php = lines.findIndex((l) => l.startsWith('  location ~ \\.php$ {'));
    expect(lines[php + 1]).toMatch(/^ {4}include \/etc\/nginx\/smartguard\/auth-php\.conf;/);
    // el server que solo redirige queda igual
    expect(r.text.slice(0, r.text.indexOf('}\n') + 2)).toBe(DIRECT.slice(0, DIRECT.indexOf('}\n') + 2));
    expect(parseVhost(r.text)).toMatchObject({ rules: true, decision: true });
  });

  it('plantilla CloudPanel: protege la entrada 80/443 y su proxy al backend; el backend 8080 no se toca', () => {
    const r = protectVhost(CLOUDPANEL);
    expect(r).toMatchObject({ rules: true, decision: true });
    expect(r.changes).toHaveLength(3);
    const backend = r.text.slice(r.text.indexOf('listen 8080;'));
    expect(backend).not.toContain('smartguard');
    const lines = r.text.split('\n');
    const proxy = lines.findIndex((l) => l.startsWith('  location / {'));
    expect(lines[proxy + 1]).toContain('include /etc/nginx/smartguard/auth-php.conf;');
    // la location de estáticos no consulta a SmartGuard
    expect(lines[lines.findIndex((l) => l.includes('css|js')) + 1]).toContain('expires max;');
  });

  it('aplicativo con proxy a otro puerto: solo reglas y límites, con aviso', () => {
    const r = protectVhost(APP);
    expect(r).toMatchObject({ rules: true, decision: false });
    expect(r.changes).toHaveLength(2);
    expect(r.warnings[0]).toContain('Parcial');
    expect(r.text).not.toContain('auth-php.conf');
  });

  it.each([['DIRECT', DIRECT], ['CLOUDPANEL', CLOUDPANEL], ['APP', APP]])('%s: es idempotente y unprotect devuelve el original', (_n, src) => {
    const once = protectVhost(src);
    const twice = protectVhost(once.text);
    expect(twice.changes).toEqual([]);
    expect(twice.text).toBe(once.text);
    const back = unprotectVhost(once.text);
    expect(back.text).toBe(src);
    expect(back.changes).toHaveLength(once.changes.length);
  });

  it('conserva los finales de línea CRLF', () => {
    const crlf = DIRECT.replace(/\n/g, '\r\n');
    const r = protectVhost(crlf);
    expect(r.text.replace(/\r\n/g, '')).not.toContain('\n');
    expect(unprotectVhost(r.text).text).toBe(crlf);
  });

  it('unprotect quita también los include escritos a mano y avisa si no hay ninguno', () => {
    const manual = 'server {\n  server_name x.test;\n  include /etc/nginx/smartguard/server.conf;   # ← al principio\n  root /x;\n}\n';
    expect(unprotectVhost(manual).text).toBe('server {\n  server_name x.test;\n  root /x;\n}\n');
    expect(unprotectVhost(APP).warnings).toHaveLength(1);
  });
});
