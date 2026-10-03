import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { NginxSitesService, parseVhost } from '../../src/admin/nginx-sites.service';

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

  it('lista los sitios de una carpeta: protegidos primero, exentos marcados, sin los archivos propios', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sg-sites-'));
    await fs.writeFile(path.join(dir, 'shop.test.conf'), PROTECTED);
    await fs.writeFile(path.join(dir, 'api.shop.test.conf'), COMMENTED);
    await fs.writeFile(path.join(dir, '00-smartguard.conf'), 'server { server_name ignored.test; }');
    await fs.writeFile(path.join(dir, 'maps.conf'), 'map $a $b { default 0; }');
    const svc = new NginxSitesService({ hostAllowed: (h: string) => h === 'api.shop.test' } as never);
    const r = await svc.list([dir, path.join(dir, 'no-existe')]);
    expect(r.readable).toBe(true);
    expect(r.items.map((s) => [s.file, s.status, s.exempt])).toEqual([
      ['shop.test.conf', 'full', false],
      ['api.shop.test.conf', 'none', true],
    ]);
    await fs.rm(dir, { recursive: true });
  });
});
