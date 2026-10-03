import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { NginxSitesService, parseVhost, primaryName } from '../../src/admin/nginx-sites.service';

const PROTECTED = `
# include /etc/nginx/smartguard/auth-php.conf;  (comentario: no cuenta)
server { listen 80; server_name www.shop.test; return 301 https://shop.test$request_uri; }
server {
  server_name shop.test www1.shop.test;
  include /etc/nginx/smartguard/server.conf;
  include /etc/nginx/smartguard/auth.conf;
  location ~ \.php$ {
    include /etc/nginx/smartguard/auth-php.conf;   # [SmartGuard]
    fastcgi_pass 127.0.0.1:9000;
  }
}`;
const COMMENTED = `
server {
  server_name api.shop.test;
  # include /etc/nginx/smartguard/server.conf;
  location / { proxy_pass http://127.0.0.1:3000; }
}`;

describe('Sitios de Nginx protegidos', () => {
  it('reconoce los include activos e ignora los comentados', () => {
    expect(parseVhost(PROTECTED)).toEqual({ names: ['www.shop.test', 'shop.test', 'www1.shop.test'], kind: 'php', rules: true, decision: true, staticLog: false });
    expect(parseVhost(COMMENTED)).toMatchObject({ names: ['api.shop.test'], kind: 'proxy', rules: false, decision: false });
    expect(parseVhost('server { server_name s.test; include /etc/nginx/smartguard/server.conf; root /var/www; }')).toMatchObject({ kind: 'static', rules: true, decision: false });
  });

  it('nombre principal: el del archivo del vhost si es uno de sus dominios; si no, el más corto', () => {
    expect(primaryName('shop.test.conf', ['www.shop.test', 'shop.test', 'www1.shop.test'])).toBe('shop.test');
    expect(primaryName('custom-domain.conf', ['panel.shop.test', 'cp.shop.test'])).toBe('cp.shop.test');
  });

  it('lista los sitios de una carpeta: protegidos primero, exentos marcados, sin los archivos propios', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sg-sites-'));
    await fs.mkdir(path.join(dir, 'vista-vacia'));
    await fs.writeFile(path.join(dir, 'shop.test.conf'), PROTECTED);
    await fs.writeFile(path.join(dir, 'api.shop.test.conf'), COMMENTED);
    await fs.writeFile(path.join(dir, '00-smartguard.conf'), 'server { server_name ignored.test; }');
    await fs.writeFile(path.join(dir, 'maps.conf'), 'map $a $b { default 0; }');
    const svc = new NginxSitesService({ hostAllowed: (h: string) => h === 'api.shop.test' } as never);
    const r = await svc.list([[path.join(dir, 'vista-vacia'), dir], [path.join(dir, 'no-existe')]]);
    expect(r.readable).toBe(true);
    expect(r.items.map((s) => [s.file, s.primary, s.status, s.exempt])).toEqual([
      ['shop.test.conf', 'shop.test', 'full', false],
      ['api.shop.test.conf', 'api.shop.test', 'none', true],
    ]);
    expect(await svc.groups()).toEqual(new Map());
    await fs.rm(dir, { recursive: true });
  });

  it('un vhost que cambia se ve en la siguiente consulta, sin esperar a que caduque la lectura guardada', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sg-sites-'));
    const file = path.join(dir, 'api.shop.test.conf');
    await fs.writeFile(file, COMMENTED);
    const svc = new NginxSitesService({ hostAllowed: () => false } as never);
    const dirs = [[dir]];
    expect((await svc.list(dirs)).items.map((s) => s.status)).toEqual(['none']);
    // lo que hace «smartguard protect»: reescribe el vhost con los include
    await fs.writeFile(file, PROTECTED);
    expect((await svc.list(dirs)).items.map((s) => s.status)).toEqual(['full']);
    await fs.rm(dir, { recursive: true });
  });
});

describe('Sitios de Nginx: permisos', () => {
  it('una carpeta que existe pero no se puede listar se informa como sin acceso', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sg-sites-'));
    const notADir = path.join(dir, 'archivo');
    await fs.writeFile(notADir, 'x');
    const svc = new NginxSitesService({ hostAllowed: () => false } as never);
    // listar un archivo falla con ENOTDIR: mismo camino que un EACCES
    expect(await svc.list([[notADir]])).toMatchObject({ readable: false, dirs: [notADir], items: [] });
    expect(await svc.list([[path.join(dir, 'no-existe')]])).toMatchObject({ readable: true, items: [] });
    await fs.rm(dir, { recursive: true });
  });
});
