import 'reflect-metadata';
import { Test } from '@nestjs/testing';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { AppModule } from '../../src/app.module';
import { ConfigService } from '../../src/config/config.service';
import { configureApp, createAdapter } from '../../src/main';
import { BlocklistService } from '../../src/blocklist/blocklist.service';
import { IpInfoService } from '../../src/ipinfo/ipinfo.service';
import { StatsService } from '../../src/stats/stats.service';
import { testEnv } from '../helpers';

const SECRET = 'test-decision-secret-0123456789';
const TOKEN = 'test-admin-token-0123456789abcdef0123456789';

function decisionHeaders(ip: string, uri: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    'x-smartguard-key': SECRET,
    'x-real-ip': ip,
    'x-tcp-ip': '172.64.1.1', // edge de Cloudflare
    'x-original-uri': uri,
    'x-original-method': 'GET',
    'x-user-agent': 'Mozilla/5.0 Test',
    'x-host': 'orleansembroidery.com',
    'x-request-id': 'abcdef0123456789',
    'x-country': 'PE',
    ...extra,
  };
}

async function makeApp(vars: Record<string, string>): Promise<NestFastifyApplication> {
  const config = new ConfigService(testEnv(vars));
  await config.loadFiles();
  const mod = await Test.createTestingModule({ imports: [AppModule.forRoot({ config })] }).compile();
  const app = mod.createNestApplication<NestFastifyApplication>(createAdapter());
  configureApp(app);
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
  return app;
}

describe('API HTTP (Nest + Fastify, sin Redis)', () => {
  let app: NestFastifyApplication;

  beforeAll(async () => {
    app = await makeApp({ AUDIT_MODE: 'false' });
  });
  afterAll(async () => {
    await app.close();
  });

  const decide = (ip: string, uri: string, extra?: Record<string, string>) =>
    app.inject({ method: 'GET', url: '/internal/decision', headers: decisionHeaders(ip, uri, extra), remoteAddress: '127.0.0.1' });

  it('visitante normal → 200 ALLOW', async () => {
    const r = await decide('198.51.100.1', '/shop/');
    expect(r.statusCode).toBe(200);
    expect(r.headers['x-smartguard-decision']).toBe('ALLOW');
    expect(r.body).toBe('');
  });

  it('scanner → 403 BLOCK y queda baneado', async () => {
    const codes: number[] = [];
    for (const uri of ['/.env', '/.git/config', '/shell.php', '/phpinfo.php']) codes.push((await decide('192.0.2.200', uri)).statusCode);
    expect(codes).toContain(403);
    const r = await decide('192.0.2.200', '/');
    expect(r.statusCode).toBe(403);
    expect(r.headers['x-smartguard-decision']).toBe('BLOCK');
  });

  it('sin X-SmartGuard-Key no evalúa ni puntúa (200 UNAUTHENTICATED)', async () => {
    const r = await app.inject({
      method: 'GET',
      url: '/internal/decision',
      headers: { ...decisionHeaders('192.0.2.201', '/.env'), 'x-smartguard-key': 'wrong' },
      remoteAddress: '127.0.0.1',
    });
    expect(r.statusCode).toBe(200);
    expect(r.headers['x-smartguard-decision']).toBe('UNAUTHENTICATED');
  });

  it('rechaza llamadas que no vienen de loopback', async () => {
    const r = await app.inject({ method: 'GET', url: '/internal/decision', headers: decisionHeaders('192.0.2.202', '/'), remoteAddress: '203.0.113.9' });
    expect(r.statusCode).toBe(403);
  });

  it('IP inválida en X-Real-IP → 200 (fail-open)', async () => {
    const r = await decide('not-an-ip', '/');
    expect(r.statusCode).toBe(200);
    expect(r.headers['x-smartguard-decision']).toBe('NO_IP');
  });

  it('IPv6 funciona extremo a extremo', async () => {
    for (const uri of ['/.env', '/.git/config', '/wso.php']) await decide('2001:db8:beef:1::1', uri);
    const r = await decide('2001:db8:beef:1::2', '/');
    expect(r.statusCode).toBe(403);
  });

  it('/health responde', async () => {
    const r = await app.inject({ method: 'GET', url: '/health', remoteAddress: '127.0.0.1' });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ status: 'ok', mode: 'ENFORCE' });
  });

  it('/metrics expone métricas Prometheus', async () => {
    const r = await app.inject({ method: 'GET', url: '/metrics', remoteAddress: '127.0.0.1' });
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain('smartguard_requests_total');
    expect(r.body).toContain('smartguard_decision_duration_seconds');
  });

  it('API admin exige token', async () => {
    expect((await app.inject({ method: 'GET', url: '/admin/bans', remoteAddress: '127.0.0.1' })).statusCode).toBe(401);
    const ok = await app.inject({ method: 'GET', url: '/admin/bans', headers: { authorization: `Bearer ${TOKEN}` }, remoteAddress: '127.0.0.1' });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().total).toBeGreaterThanOrEqual(1);
  });

  it('explicación de una IP baneada', async () => {
    const r = await app.inject({ method: 'GET', url: '/admin/ip/192.0.2.200', headers: { authorization: `Bearer ${TOKEN}` }, remoteAddress: '127.0.0.1' });
    const j = r.json();
    expect(j.explanation).toContain('env-scan +25');
    expect(j.explanation).toContain('BLOCK');
  });

  it('ban/unban manual con validación de DTO', async () => {
    const auth = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };
    const bad = await app.inject({ method: 'POST', url: '/admin/ban', headers: auth, payload: { ip: '1.2.3.4; rm -rf /' }, remoteAddress: '127.0.0.1' });
    expect(bad.statusCode).toBe(400);
    const extra = await app.inject({ method: 'POST', url: '/admin/ban', headers: auth, payload: { ip: '192.0.2.210', evil: 1 }, remoteAddress: '127.0.0.1' });
    expect(extra.statusCode).toBe(400);
    const cf = await app.inject({ method: 'POST', url: '/admin/ban', headers: auth, payload: { ip: '172.64.1.1' }, remoteAddress: '127.0.0.1' });
    expect(cf.statusCode).toBe(400); // nunca banear Cloudflare
    const ok = await app.inject({ method: 'POST', url: '/admin/ban', headers: auth, payload: { ip: '192.0.2.210', duration: '2h', reason: 'test' }, remoteAddress: '127.0.0.1' });
    expect(ok.statusCode).toBe(201);
    expect(ok.json().durationSec).toBe(7200);
    expect((await decide('192.0.2.210', '/')).statusCode).toBe(403);
    const del = await app.inject({ method: 'DELETE', url: '/admin/ban/192.0.2.210', headers: { authorization: `Bearer ${TOKEN}` }, remoteAddress: '127.0.0.1' });
    expect(del.json().removed).toBe(true);
    expect((await decide('192.0.2.210', '/')).statusCode).toBe(200);
  });

  it('allowlist por API: IP (desbloquea), subdominios de cliente y host exento', async () => {
    const auth = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };
    const post = (payload: unknown) => app.inject({ method: 'POST', url: '/admin/allow', headers: auth, payload: payload as object, remoteAddress: '127.0.0.1' });
    // IP baneada (del test del scanner) → allow la desbloquea y ya no se bloquea
    const a = await post({ value: '192.0.2.200', type: 'ADMIN_ALLOWLIST', note: 'yo' });
    expect(a.statusCode).toBe(201);
    expect(a.json().unban.removed).toBe(true);
    expect((await decide('192.0.2.200', '/.env')).statusCode).toBe(200);
    // subdominios de cliente
    expect((await post({ value: '*.customily.com', type: 'SERVICE_ALLOWLIST' })).statusCode).toBe(201);
    // host destino exento
    expect((await post({ value: 'apicustomizer.orleansembroidery.com', target: 'host' })).statusCode).toBe(201);
    const exempt = await decide('192.0.2.240', '/.env', { 'x-host': 'apicustomizer.orleansembroidery.com' });
    expect(exempt.headers['x-smartguard-decision']).toBe('ALLOW');
    // validación
    expect((await post({ value: 'no válido!' })).statusCode).toBe(400);
    expect((await post({ value: '1.2.3.4', target: 'host' })).statusCode).toBe(400);
    expect((await post({ value: 'x.com', type: 'ROOT' })).statusCode).toBe(400);
    const list = await app.inject({ method: 'GET', url: '/admin/allow', headers: { authorization: `Bearer ${TOKEN}` }, remoteAddress: '127.0.0.1' });
    expect(list.json().dynamic.map((e: { value: string }) => e.value)).toEqual(
      expect.arrayContaining(['192.0.2.200/32', '*.customily.com', 'apicustomizer.orleansembroidery.com']),
    );
    const del = await app.inject({
      method: 'DELETE',
      url: `/admin/allow/${encodeURIComponent('*.customily.com')}`,
      headers: { authorization: `Bearer ${TOKEN}` },
      remoteAddress: '127.0.0.1',
    });
    expect(del.json().removed).toBe(true);
  });

  it('query inválida en listados → 400', async () => {
    const r = await app.inject({ method: 'GET', url: '/admin/bans?limit=abc', headers: { authorization: `Bearer ${TOKEN}` }, remoteAddress: '127.0.0.1' });
    expect(r.statusCode).toBe(400);
  });

  it('cambio a AUDIT en caliente: deja de bloquear', async () => {
    const auth = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };
    const r = await app.inject({ method: 'POST', url: '/admin/mode', headers: auth, payload: { audit: true }, remoteAddress: '127.0.0.1' });
    expect(r.json().mode).toBe('AUDIT');
    const d = await decide('192.0.2.220', '/.env');
    expect(d.statusCode).toBe(200);
    await app.inject({ method: 'POST', url: '/admin/mode', headers: auth, payload: { audit: false }, remoteAddress: '127.0.0.1' });
  });

  it('recarga de reglas', async () => {
    const r = await app.inject({ method: 'POST', url: '/admin/rules/reload', headers: { authorization: `Bearer ${TOKEN}` }, remoteAddress: '127.0.0.1' });
    expect(r.statusCode).toBe(200);
    expect(r.json().ok).toBe(true);
  });

  it('dashboard Angular: index con nonce y CSP estricta, assets y rutas protegidas', async () => {
    const redir = await app.inject({ method: 'GET', url: '/dashboard', remoteAddress: '127.0.0.1' });
    expect(redir.statusCode).toBe(302);
    const r = await app.inject({ method: 'GET', url: '/dashboard/', remoteAddress: '127.0.0.1' });
    if (r.statusCode === 503) return; // dashboard no compilado en este entorno
    expect(r.statusCode).toBe(200);
    const csp = String(r.headers['content-security-policy']);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    const nonce = /'nonce-([^']+)'/.exec(csp)![1]!;
    expect(r.body).toContain('ngcspnonce="' + nonce + '"');
    expect(r.body).not.toContain('__CSP_NONCE__');
    const js = /src="(main-[^"]+\.js)"/.exec(r.body)![1]!;
    const asset = await app.inject({ method: 'GET', url: '/dashboard/' + js, remoteAddress: '127.0.0.1' });
    expect(asset.statusCode).toBe(200);
    expect(asset.headers['content-type']).toContain('javascript');
    const trav = await app.inject({ method: 'GET', url: '/dashboard/..%2f..%2fpackage.json', remoteAddress: '127.0.0.1' });
    expect(trav.statusCode).toBe(404);
    const remote = await app.inject({ method: 'GET', url: '/dashboard/', remoteAddress: '203.0.113.9' });
    expect(remote.statusCode).toBe(403);
  });

  it('lookup y conflictos: bloquear una IP de la allowlist o ya bloqueada devuelve 409 con detalle', async () => {
    const auth = { authorization: 'Bearer ' + TOKEN, 'content-type': 'application/json' };
    const get = (v: string) => app.inject({ method: 'GET', url: '/admin/lookup?value=' + encodeURIComponent(v), headers: auth, remoteAddress: '127.0.0.1' });
    const ban = (ip: string) => app.inject({ method: 'POST', url: '/admin/ban', headers: auth, payload: { ip, duration: '1h' }, remoteAddress: '127.0.0.1' });
    // 192.0.2.200 se añadió a ADMIN_ALLOWLIST en un test anterior
    const l = (await get('192.0.2.200')).json();
    expect(l.allowlisted).toBe(true);
    expect(l.allowlist[0]).toMatchObject({ list: 'ADMIN_ALLOWLIST', source: 'dynamic', matchedBy: 'exact' });
    const b1 = await ban('192.0.2.200');
    expect(b1.statusCode).toBe(409);
    expect(b1.json()).toMatchObject({ code: 'IP_ALLOWLISTED', params: { matches: [{ list: 'ADMIN_ALLOWLIST' }] } });
    expect((await ban('192.0.2.250')).statusCode).toBe(201);
    const b2 = await ban('192.0.2.250');
    expect(b2.statusCode).toBe(409);
    expect(b2.json().code).toBe('ALREADY_BANNED');
    const l2 = (await get('192.0.2.250')).json();
    expect(l2.banned).toBe(true);
    expect(l2.ban.expiresAt).toBeGreaterThan(Date.now());
    const dup = await app.inject({ method: 'POST', url: '/admin/allow', headers: auth, payload: { value: '192.0.2.200' }, remoteAddress: '127.0.0.1' });
    expect(dup.statusCode).toBe(409);
    expect(dup.json().code).toBe('ALREADY_ALLOWLISTED');
    expect((await get('no valido!')).statusCode).toBe(400);
    expect((await get('172.64.1.1')).json().isCloudflare).toBe(true);
  });
});

describe('AUDIT_MODE=true (instalación inicial)', () => {
  let app: NestFastifyApplication;
  beforeAll(async () => {
    app = await makeApp({ AUDIT_MODE: 'true' });
  });
  afterAll(async () => {
    await app.close();
  });

  it('nunca devuelve 403/429 y etiqueta WOULD_BLOCK', async () => {
    let last;
    for (const uri of ['/.env', '/.git/config', '/shell.php', '/phpinfo.php', '/']) {
      last = await app.inject({ method: 'GET', url: '/internal/decision', headers: decisionHeaders('192.0.2.230', uri), remoteAddress: '127.0.0.1' });
      expect(last.statusCode).toBe(200);
    }
    expect(last!.headers['x-smartguard-decision']).toBe('WOULD_BLOCK');
  });

  it('/admin/ipinfo valida la lista de IPs y no consulta DNS para IPs privadas', async () => {
    const auth = { authorization: `Bearer ${TOKEN}` };
    const get = (ips: string) => app.inject({ method: 'GET', url: `/admin/ipinfo?ips=${encodeURIComponent(ips)}`, headers: auth, remoteAddress: '127.0.0.1' });
    const ok = await get('10.0.0.1,127.0.0.1');
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toEqual({ items: { '10.0.0.1': null, '127.0.0.1': null } });
    expect((await get('no-es-ip')).statusCode).toBe(400);
    expect((await get(Array.from({ length: 51 }, (_, i) => `10.0.0.${i}`).join(','))).statusCode).toBe(400);
    expect((await app.inject({ method: 'GET', url: '/admin/ipinfo?ips=10.0.0.1', remoteAddress: '127.0.0.1' })).statusCode).toBe(401);
  });

  it('red completa (ASN): API de alta/listado/baja y 403 para sus IPs también en AUDIT', async () => {
    app.get(BlocklistService).setPrefixFetcher(async () => ['203.0.113.0/24', '2001:db8:100::/40']);
    app.get(IpInfoService).setResolver({ resolveTxt: async () => Promise.reject(new Error('sin DNS')) });
    const auth = { authorization: `Bearer ${TOKEN}` };
    const admin = (method: 'GET' | 'POST' | 'DELETE', url: string, payload?: object) =>
      app.inject({ method, url, headers: auth, payload, remoteAddress: '127.0.0.1' });
    const decide = (ip: string) =>
      app.inject({ method: 'GET', url: '/internal/decision', headers: decisionHeaders(ip, '/shop/'), remoteAddress: '127.0.0.1' });

    expect((await admin('POST', '/admin/blocked-networks', {})).statusCode).toBe(400);
    expect((await admin('POST', '/admin/blocked-networks', { asn: 13335 })).json()).toMatchObject({ code: 'NETWORK_PROTECTED' });
    const add = await admin('POST', '/admin/blocked-networks', { asn: 64500, note: 'test' });
    expect(add.statusCode).toBe(201);
    expect(add.json()).toMatchObject({ asn: 64500, prefixCount: 2, note: 'test' });
    expect((await admin('GET', '/admin/blocked-networks')).json().items).toEqual([expect.objectContaining({ asn: 64500, prefixCount: 2 })]);

    const blocked = await decide('203.0.113.77');
    expect(blocked.statusCode).toBe(403);
    expect(blocked.headers['x-smartguard-decision']).toBe('BLOCK');
    expect((await decide('2001:db8:1aa::9')).statusCode).toBe(403);
    expect((await decide('198.51.100.77')).statusCode).toBe(200);

    expect((await admin('DELETE', '/admin/blocked-networks?asn=64500')).json()).toEqual({ removed: true });
    expect((await decide('203.0.113.77')).statusCode).toBe(200);
    expect((await admin('DELETE', '/admin/blocked-networks?asn=64500')).statusCode).toBe(404);
  });

  it('bloqueos manuales (bot por nombre e IP) devuelven 403 también en AUDIT', async () => {
    const auth = { authorization: `Bearer ${TOKEN}` };
    const admin = (method: 'GET' | 'POST' | 'DELETE', url: string, payload?: object) =>
      app.inject({ method, url, headers: auth, payload, remoteAddress: '127.0.0.1' });
    const decide = (ip: string, ua: string) =>
      app.inject({ method: 'GET', url: '/internal/decision', headers: decisionHeaders(ip, '/shop/', { 'x-user-agent': ua }), remoteAddress: '127.0.0.1' });
    const dotbot = 'Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)';

    expect((await decide('198.51.100.90', dotbot)).statusCode).toBe(200);

    // bot por nombre
    expect((await admin('POST', '/admin/blocked-bots', { pattern: 'Chrome' })).json()).toMatchObject({ code: 'BOT_PATTERN_TOO_GENERIC' });
    const add = await admin('POST', '/admin/blocked-bots', { pattern: 'DotBot', note: 'test' });
    expect(add.statusCode).toBe(201);
    expect(add.json()).toMatchObject({ pattern: 'dotbot', note: 'test' });
    expect((await admin('GET', '/admin/blocked-bots')).json().items).toEqual([expect.objectContaining({ pattern: 'dotbot' })]);
    const blocked = await decide('198.51.100.90', dotbot);
    expect(blocked.statusCode).toBe(403);
    expect(blocked.headers['x-smartguard-decision']).toBe('BLOCK');
    expect((await decide('198.51.100.90', 'Mozilla/5.0 Test')).statusCode).toBe(200);
    expect((await admin('DELETE', '/admin/blocked-bots?pattern=DotBot')).json()).toEqual({ removed: true });
    expect((await decide('198.51.100.90', dotbot)).statusCode).toBe(200);
    expect((await admin('DELETE', '/admin/blocked-bots?pattern=dotbot')).statusCode).toBe(404);

    // IP
    // "hasta que se desbloquee" = 10 años (3650d); una duración mayor se recorta a ese máximo
    const year = 365 * 86_400_000;
    const forever = await admin('POST', '/admin/ban', { ip: '198.51.100.91', duration: '3650d' });
    expect(forever.statusCode).toBe(201);
    expect(forever.json().expiresAt - Date.now()).toBeGreaterThan(9.9 * year);
    const capped = await admin('POST', '/admin/ban', { ip: '198.51.100.92', duration: '9999999w' });
    expect(capped.json().expiresAt - Date.now()).toBeLessThan(10.1 * year);
    expect((await admin('GET', '/admin/bans')).json().items.map((b: { key: string }) => b.key)).toEqual(
      expect.arrayContaining(['198.51.100.91', '198.51.100.92']),
    );
    expect((await decide('198.51.100.91', 'Mozilla/5.0 Test')).statusCode).toBe(403);
    expect((await admin('DELETE', '/admin/ban/198.51.100.91')).statusCode).toBe(200);
    expect((await decide('198.51.100.91', 'Mozilla/5.0 Test')).statusCode).toBe(200);
  });
});

describe('Estadísticas por sitio (API)', () => {
  let app: NestFastifyApplication;
  beforeAll(async () => {
    app = await makeApp({ AUDIT_MODE: 'false' });
  });
  afterAll(async () => {
    await app.close();
  });
  const decide = (ip: string, uri: string, extra?: Record<string, string>) =>
    app.inject({ method: 'GET', url: '/internal/decision', headers: decisionHeaders(ip, uri, extra), remoteAddress: '127.0.0.1' });

  it('estadísticas y eventos por sitio: total, un sitio y lista de sitios con datos', async () => {
    const get = (url: string) => app.inject({ method: 'GET', url, headers: { authorization: `Bearer ${TOKEN}` }, remoteAddress: '127.0.0.1' });
    await decide('198.51.100.120', '/.env', { 'x-host': 'otra-tienda.test' });
    await decide('198.51.100.121', '/', { 'x-host': 'otra-tienda.test' });
    await decide('198.51.100.122', '/');
    await app.get(StatsService).flush();
    const all = (await get('/admin/stats?minutes=5')).json();
    const one = (await get('/admin/stats?minutes=5&host=otra-tienda.test')).json();
    expect(all.hosts).toEqual(expect.arrayContaining(['otra-tienda.test', 'orleansembroidery.com']));
    expect(one.host).toBe('otra-tienda.test');
    expect(one.totals.requests).toBe(2);
    expect(all.totals.requests).toBeGreaterThan(one.totals.requests);
    // en la respuesta no quedan campos con el prefijo interno por sitio
    expect(Object.keys(all.totals).some((k) => k.startsWith('h:'))).toBe(false);
    expect(one.topPaths.map((p: { member: string }) => p.member)).toEqual(['/.env']);
    // el evento de un sitio que no está en sites.yaml guarda su dominio real y se puede filtrar por él
    const events = (await get('/admin/events/page?limit=50&host=otra-tienda.test')).json();
    expect(events.items.length).toBeGreaterThanOrEqual(1);
    expect(events.items.every((e: { host: string }) => e.host === 'otra-tienda.test')).toBe(true);
    expect((await get('/admin/stats?host=No%20Valido')).statusCode).toBe(400);
  });
});
