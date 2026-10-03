import { makeHarness } from '../helpers';
import { parseAllowValue } from '../../src/whitelist/allowlist.service';
import { parseDomainPattern, domainMatches } from '../../src/common/dns.util';
import { parseIp } from '../../src/common/ip.util';
import { ApiError } from '../../src/common/api-error';
import { field, validate } from '../../src/common/validation';

const SCANNER = ['/.env', '/.git/config', '/shell.php', '/phpinfo.php'];

describe('Valores de allowlist', () => {
  it.each([
    ['203.0.113.36', 'cidr', '203.0.113.36/32'],
    ['10.0.0.0/8', 'cidr', '10.0.0.0/8'],
    ['2001:db8::/48', 'cidr', '2001:db8::/48'],
    ['App.Customily.com', 'domain', 'app.customily.com'],
    ['*.customily.com', 'wildcard', '*.customily.com'],
    ['.stripe.com', 'wildcard', '*.stripe.com'],
    ['1ab.cd', 'domain', '1ab.cd'],
  ])('%s → %s', (input, kind, value) => {
    const p = parseAllowValue(input);
    expect(p?.kind).toBe(kind);
    expect(p?.value).toBe(value);
  });

  it.each(['1.2.3', 'localhost', '*.com', 'a..b.com', '-x.com', 'exa mple.com', '999.1.1.1/40', '*.*.x.com'])('rechaza %s', (v) => {
    expect(parseAllowValue(v)).toBeNull();
  });

  it('coincidencia de subdominios', () => {
    const p = parseDomainPattern('*.orleansembroidery.com')!;
    expect(domainMatches('apicustomizer.orleansembroidery.com', p)).toBe(true);
    expect(domainMatches('orleansembroidery.com', p)).toBe(true);
    expect(domainMatches('evilorleansembroidery.com', p)).toBe(false);
    expect(domainMatches('orleansembroidery.com.evil.net', p)).toBe(false);
    const exact = parseDomainPattern('app.customily.com')!;
    expect(domainMatches('x.app.customily.com', exact)).toBe(false);
  });
});

describe('Allowlist por dominio / subdominio / host', () => {
  it('dominio exacto: se resuelve a sus IPs y esas IPs nunca se bloquean', async () => {
    const h = await makeHarness({ SERVICE_ALLOWLIST: 'app.customily.com' });
    h.resolver.a.set('app.customily.com', ['198.51.100.140']);
    await h.allowlist.resolveDomains();
    for (const uri of SCANNER) {
      const d = await h.scoring.decide(h.req({ ip: '198.51.100.140', uri }));
      expect(d.action).toBe('ALLOW');
      expect(d.basis).toBe('allowlist:SERVICE_ALLOWLIST');
    }
  });

  it('subdominios (*.dominio): FCrDNS solo se consulta ante señales y luego exime', async () => {
    const h = await makeHarness();
    await h.allowlist.add('*.customily.com', 'SERVICE_ALLOWLIST', 'client', 'test');
    h.resolver.ptr.set('198.51.100.141', ['render-3.eu.customily.com']);
    h.resolver.a.set('render-3.eu.customily.com', ['198.51.100.141']);
    // tráfico normal: no dispara ninguna consulta DNS
    await h.scoring.decide(h.req({ ip: '198.51.100.141', uri: '/' }));
    await h.allowlist.drain();
    expect(h.allowlist.classify(parseIp('198.51.100.141')!)).toBeNull();
    // petición sospechosa: se verifica en segundo plano
    await h.scoring.decide(h.req({ ip: '198.51.100.141', uri: '/.env' }));
    await h.allowlist.drain();
    const d = await h.scoring.decide(h.req({ ip: '198.51.100.141', uri: '/.git/config' }));
    expect(d.basis).toBe('allowlist:SERVICE_ALLOWLIST');
  });

  it('subdominio con PTR falsificado (no resuelve a la IP) NO queda permitido', async () => {
    const h = await makeHarness();
    await h.allowlist.add('*.customily.com', 'SERVICE_ALLOWLIST', 'client', 'test');
    h.resolver.ptr.set('198.51.100.142', ['fake.customily.com']);
    h.resolver.a.set('fake.customily.com', ['203.0.113.1']);
    await h.scoring.decide(h.req({ ip: '198.51.100.142', uri: '/.env' }));
    await h.allowlist.drain();
    expect(h.allowlist.classify(parseIp('198.51.100.142')!)).toBeNull();
  });

  it('host destino exento (ALLOW_HOSTS): subdominios propios no se puntúan', async () => {
    const h = await makeHarness({ ALLOW_HOSTS: 'apicustomizer.orleansembroidery.com,*.dev.orleansembroidery.com' });
    const a = await h.scoring.decide(h.req({ ip: '192.0.2.150', uri: '/.env', host: 'apicustomizer.orleansembroidery.com' }));
    expect(a.basis).toBe('allowlist:HOST');
    const b = await h.scoring.decide(h.req({ ip: '192.0.2.150', uri: '/.env', host: 'x.dev.orleansembroidery.com' }));
    expect(b.basis).toBe('allowlist:HOST');
    // el sitio principal sigue protegido
    for (const uri of SCANNER) await h.scoring.decide(h.req({ ip: '192.0.2.151', uri }));
    expect((await h.scoring.decide(h.req({ ip: '192.0.2.151', uri: '/' }))).action).toBe('BLOCK');
  });

  it('host exento dinámico vía API (target=host) y no admite IPs', async () => {
    const h = await makeHarness();
    await h.allowlist.add('*.staging.example.com', 'SERVICE_ALLOWLIST', 'host', 'staging');
    expect(h.allowlist.hostAllowed('shop.staging.example.com')).toBe(true);
    await expect(h.allowlist.add('1.2.3.4', 'ADMIN_ALLOWLIST', 'host', '')).rejects.toThrow();
    await h.allowlist.remove('*.staging.example.com');
    expect(h.allowlist.hostAllowed('shop.staging.example.com')).toBe(false);
  });
});

describe('Desbloqueo completo', () => {
  it('unban quita ban de IP, bans de huella y resetea el score (no se re-banea al instante)', async () => {
    const h = await makeHarness();
    for (const uri of SCANNER) await h.scoring.decide(h.req({ ip: '192.0.2.160', uri }));
    for (let i = 1; i <= 15; i++) await h.scoring.decide(h.req({ ip: '192.0.2.160', uri: `/?author=${i}`, userAgent: '' }));
    expect(await h.bans.getBan('ip', '192.0.2.160')).not.toBeNull();
    const ip = parseIp('192.0.2.160')!;
    const r = await h.bans.unban(ip, '192.0.2.160');
    expect(r.removed).toBe(true);
    expect(r.reset).toBe(true);
    expect(await h.reputation.call((s) => s.getIpState('192.0.2.160'))).toBeNull();
    // una señal leve posterior ya no provoca un ban inmediato
    const d = await h.scoring.decide(h.req({ ip: '192.0.2.160', uri: '/wp-json/wp/v2/users' }));
    expect(d.action).not.toBe('BLOCK');
    const d2 = await h.scoring.decide(h.req({ ip: '192.0.2.160', uri: '/', userAgent: '' }));
    expect(d2.action).toBe('ALLOW');
  });

  it('unban con reset=false conserva el historial', async () => {
    const h = await makeHarness();
    for (const uri of SCANNER) await h.scoring.decide(h.req({ ip: '192.0.2.161', uri }));
    await h.bans.unban(parseIp('192.0.2.161')!, '192.0.2.161', { reset: false });
    expect(await h.bans.getBan('ip', '192.0.2.161')).toBeNull();
    expect((await h.reputation.call((s) => s.getIpState('192.0.2.161')))!.score).toBeGreaterThan(80);
  });
});

describe('Validación por decoradores (sin DTOs)', () => {
  const schema = { ip: field.ip(), duration: field.optional(field.duration()), firewall: field.optional(field.boolean()) };

  it('acepta y tipa valores válidos', () => {
    expect(validate(schema, { ip: '1.2.3.4', duration: '2h', firewall: true }, 'body')).toEqual({ ip: '1.2.3.4', duration: '2h', firewall: true });
  });

  it.each([
    [{}, 'ip: required'],
    [{ ip: '1.2.3.4; rm -rf /' }, 'ip:'],
    [{ ip: '1.2.3.4', duration: '1 year' }, 'duration:'],
    [{ ip: '1.2.3.4', extra: 1 }, 'field not allowed'],
    [[1, 2], 'a JSON object was expected'],
  ])('rechaza %j', (input, msg) => {
    try {
      validate(schema, input, 'body');
      throw new Error('no lanzó');
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      const body = (e as ApiError).getResponse() as { code: string };
      expect(body.code).toBe('VALIDATION');
      expect(JSON.stringify(body)).toContain(msg);
    }
  });
});

describe('Consulta (lookup) y duplicados: dice EN QUÉ lista está', () => {
  it('IP dentro de un CIDR del .env', async () => {
    const h = await makeHarness({ ADMIN_ALLOWLIST: '203.0.113.0/24' });
    const r = h.allowlist.lookup('203.0.113.36');
    expect(r.isIp).toBe(true);
    expect(r.matches[0]).toMatchObject({ list: 'ADMIN_ALLOWLIST', source: 'env', matchedBy: 'cidr', value: '203.0.113.0/24' });
  });

  it('IP resuelta de un dominio exacto', async () => {
    const h = await makeHarness({ SERVICE_ALLOWLIST: 'app.customily.com' });
    h.resolver.a.set('app.customily.com', ['198.51.100.140']);
    await h.allowlist.resolveDomains();
    expect(h.allowlist.lookup('198.51.100.140').matches[0]).toMatchObject({ list: 'SERVICE_ALLOWLIST', matchedBy: 'domain-resolved' });
  });

  it('duplicado exacto: 409 ALREADY_ALLOWLISTED con la lista', async () => {
    const h = await makeHarness();
    await h.allowlist.add('203.0.113.50', 'SERVICE_ALLOWLIST', 'client', 'x');
    let err: ApiError | null = null;
    try {
      await h.allowlist.add('203.0.113.50', 'ADMIN_ALLOWLIST', 'client', 'y');
    } catch (e) {
      err = e as ApiError;
    }
    expect(err).not.toBeNull();
    const body = err!.getResponse() as { code: string; params: { matches: { list: string; source: string }[] } };
    expect(err!.getStatus()).toBe(409);
    expect(body.code).toBe('ALREADY_ALLOWLISTED');
    expect(body.params.matches[0]).toMatchObject({ list: 'SERVICE_ALLOWLIST', source: 'dynamic' });
  });

  it('IP cubierta por un rango existente: 409 ALREADY_COVERED', async () => {
    const h = await makeHarness({ TRUSTED_NETWORKS: '10.20.0.0/16' });
    await expect(h.allowlist.add('10.20.3.4', 'ADMIN_ALLOWLIST', 'client', '')).rejects.toMatchObject({ response: { code: 'ALREADY_COVERED' } });
  });

  it('subdominio ya cubierto por *.dominio: 409 ALREADY_COVERED', async () => {
    const h = await makeHarness();
    await h.allowlist.add('*.customily.com', 'SERVICE_ALLOWLIST', 'client', '');
    await expect(h.allowlist.add('app.customily.com', 'SERVICE_ALLOWLIST', 'client', '')).rejects.toMatchObject({ response: { code: 'ALREADY_COVERED' } });
  });

  it('URL de sitio: se guarda el host; el duplicado se detecta', async () => {
    const h = await makeHarness();
    const e = await h.allowlist.add('https://API.Orleansembroidery.com/wp-json/x?y=1', 'SERVICE_ALLOWLIST', 'host', '');
    expect(e.value).toBe('api.orleansembroidery.com');
    expect(h.allowlist.hostAllowed('api.orleansembroidery.com')).toBe(true);
    await expect(h.allowlist.add('api.orleansembroidery.com', 'SERVICE_ALLOWLIST', 'host', '')).rejects.toMatchObject({ response: { code: 'ALREADY_ALLOWLISTED' } });
  });

  it('quitar una entrada del .env: 409 STATIC_ENTRY; inexistente: 404', async () => {
    const h = await makeHarness({ ADMIN_ALLOWLIST: '203.0.113.36' });
    await expect(h.allowlist.remove('203.0.113.36')).rejects.toMatchObject({ response: { code: 'STATIC_ENTRY' } });
    await expect(h.allowlist.remove('203.0.113.99')).rejects.toMatchObject({ response: { code: 'NOT_IN_ALLOWLIST' } });
  });
});
