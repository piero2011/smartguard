import { makeHarness } from '../helpers';
import { IpRangeSet } from '../../src/common/ip-range-set';
import { parseIp } from '../../src/common/ip.util';

const ip = (s: string) => parseIp(s)!;

describe('IpRangeSet: pertenencia a miles de redes por búsqueda binaria', () => {
  it('IPv4: límites del rango, redes anidadas y huecos', () => {
    const set = new IpRangeSet([
      { cidr: '203.0.113.0/24', tag: 'a' },
      { cidr: '198.51.100.0/24', tag: 'b' },
      { cidr: '198.51.100.128/25', tag: 'b' }, // anidada: se funde con la anterior
      { cidr: '192.0.2.7/32', tag: 'c' },
    ]);
    expect(set.find(ip('203.0.113.0'))).toBe('a');
    expect(set.find(ip('203.0.113.255'))).toBe('a');
    expect(set.find(ip('203.0.112.255'))).toBeNull();
    expect(set.find(ip('203.0.114.0'))).toBeNull();
    expect(set.find(ip('198.51.100.200'))).toBe('b');
    expect(set.find(ip('198.51.100.5'))).toBe('b');
    expect(set.find(ip('192.0.2.7'))).toBe('c');
    expect(set.find(ip('192.0.2.8'))).toBeNull();
    expect(set.find(ip('255.255.255.255'))).toBeNull();
  });

  it('IPv6 y mezcla de versiones', () => {
    const set = new IpRangeSet([
      { cidr: '2001:db8:100::/40', tag: 1 },
      { cidr: '203.0.113.0/24', tag: 2 },
    ]);
    expect(set.find(ip('2001:db8:1ff:ffff::1'))).toBe(1);
    expect(set.find(ip('2001:db8:200::1'))).toBeNull();
    expect(set.find(ip('203.0.113.9'))).toBe(2);
  });

  it('descarta entradas inválidas y prefijos que cubrirían media Internet', () => {
    const set = new IpRangeSet([
      { cidr: '0.0.0.0/0', tag: 'x' },
      { cidr: '10.0.0.0/7', tag: 'x' },
      { cidr: '::/0', tag: 'x' },
      { cidr: 'no-es-cidr', tag: 'x' },
      { cidr: '203.0.113.0/24', tag: 'ok' },
    ]);
    expect(set.size).toBe(1);
    expect(set.find(ip('8.8.8.8'))).toBeNull();
    expect(set.find(ip('2001:4860:4860::8888'))).toBeNull();
    expect(set.find(ip('203.0.113.1'))).toBe('ok');
  });

  it('coincide con una comprobación lineal sobre 2000 redes aleatorias', () => {
    let seed = 42;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const nets = Array.from({ length: 2000 }, (_, i) => {
      const bits = 16 + Math.floor(rnd() * 9); // /16…/24
      return { cidr: `${11 + Math.floor(rnd() * 200)}.${Math.floor(rnd() * 256)}.${Math.floor(rnd() * 256)}.0/${bits}`, tag: i };
    });
    const set = new IpRangeSet(nets);
    const parsed = nets.map((n) => ({ range: (ip(n.cidr.split('/')[0]!).addr as { match(o: unknown, b: number): boolean }), cidr: n.cidr }));
    for (let i = 0; i < 3000; i++) {
      const probe = ip(`${11 + Math.floor(rnd() * 200)}.${Math.floor(rnd() * 256)}.${Math.floor(rnd() * 256)}.${Math.floor(rnd() * 256)}`);
      const linear = parsed.some((p) => (probe.addr as { match(o: unknown, b: number): boolean }).match(p.range, Number(p.cidr.split('/')[1])));
      expect(set.find(probe) !== null).toBe(linear);
    }
  });
});

describe('Bloqueo de una red completa (ASN)', () => {
  const DO_PREFIXES = ['167.99.144.0/20', '159.223.0.0/20', '2604:a880:800::/48', 'basura', '0.0.0.0/0'];

  it('bloquea todas las IPs de la red (también en AUDIT) y solo esas', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true' });
    h.blocklist.setPrefixFetcher(async (asn) => (asn === 14061 ? DO_PREFIXES : []));
    const net = await h.blocklist.addNetwork({ asn: 14061 }, 'scraper');
    expect(net).toMatchObject({ asn: 14061, prefixCount: 3, note: 'scraper' }); // basura y /0 descartados

    for (const addr of ['167.99.151.99', '159.223.9.241', '2604:a880:800::1']) {
      const d = await h.scoring.decide(h.req({ ip: addr }));
      expect(d).toMatchObject({ action: 'BLOCK', audit: false, basis: 'manual:net' });
      expect(d.reasons).toContain('manual-net:AS14061');
    }
    for (const addr of ['167.99.160.1', '8.8.8.8', '2604:a880:801::1']) {
      expect((await h.scoring.decide(h.req({ ip: addr }))).action).toBe('ALLOW');
    }
  });

  it('una IP de la lista blanca dentro de la red bloqueada sigue pasando', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true', ADMIN_ALLOWLIST: '167.99.151.99' });
    h.blocklist.setPrefixFetcher(async () => DO_PREFIXES);
    await h.blocklist.addNetwork({ asn: 14061 }, '');
    expect((await h.scoring.decide(h.req({ ip: '167.99.151.99' }))).action).toBe('ALLOW');
    expect((await h.scoring.decide(h.req({ ip: '167.99.151.100' }))).action).toBe('BLOCK');
  });

  it('por IP: averigua su red; quitarla la desbloquea', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true' });
    h.blocklist.setPrefixFetcher(async () => DO_PREFIXES);
    const records: Record<string, string> = {
      '99.151.99.167.origin.asn.cymru.com': '14061 | 167.99.144.0/20 | US | arin | 2017-11-10',
      'AS14061.asn.cymru.com': '14061 | US | arin | 2012-09-25 | DIGITALOCEAN-ASN - DigitalOcean, LLC, US',
    };
    const txt = { resolveTxt: async (n: string) => (records[n] ? [[records[n]!]] : Promise.reject(new Error('ENOTFOUND'))) };
    // el arnés crea su propio IpInfoService: se le cambia el resolver a través del servicio de bloqueo
    (h.blocklist as unknown as { ipinfo: { setResolver(r: typeof txt): void } }).ipinfo.setResolver(txt);

    const net = await h.blocklist.addNetwork({ ip: '167.99.151.99' }, '');
    expect(net).toMatchObject({ asn: 14061, org: 'DigitalOcean, LLC', country: 'US' });
    expect(h.blocklist.listNetworks().map((n) => n.asn)).toEqual([14061]);
    await expect(h.blocklist.addNetwork({ asn: 14061 }, '')).rejects.toMatchObject({ response: { code: 'NETWORK_ALREADY_BLOCKED' } });

    await h.blocklist.removeNetwork(14061);
    expect((await h.scoring.decide(h.req({ ip: '167.99.151.99' }))).action).toBe('ALLOW');
    await expect(h.blocklist.removeNetwork(14061)).rejects.toMatchObject({ response: { code: 'NETWORK_NOT_BLOCKED' } });
  });

  it('nunca bloquea Cloudflare; errores claros si no hay red o falla la descarga', async () => {
    const h = await makeHarness();
    h.blocklist.setPrefixFetcher(async () => DO_PREFIXES);
    await expect(h.blocklist.addNetwork({ asn: 13335 }, '')).rejects.toMatchObject({ response: { code: 'NETWORK_PROTECTED' } });
    await expect(h.blocklist.addNetwork({ ip: '10.0.0.1' }, '')).rejects.toMatchObject({ response: { code: 'NETWORK_UNKNOWN' } });
    h.blocklist.setPrefixFetcher(async () => Promise.reject(new Error('timeout')));
    await expect(h.blocklist.addNetwork({ asn: 14061 }, '')).rejects.toMatchObject({ response: { code: 'NETWORK_FETCH_FAILED' } });
    h.blocklist.setPrefixFetcher(async () => ['basura']);
    await expect(h.blocklist.addNetwork({ asn: 14061 }, '')).rejects.toMatchObject({ response: { code: 'NETWORK_FETCH_FAILED' } });
    expect(h.blocklist.listNetworks()).toEqual([]);
  });

  it('refresco diario: actualiza los rangos y, si la descarga falla, conserva los anteriores', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true' });
    h.blocklist.setPrefixFetcher(async () => ['203.0.113.0/24']);
    await h.blocklist.addNetwork({ asn: 64500 }, '');
    const later = Date.now() + 2 * 86_400_000;

    h.blocklist.setPrefixFetcher(async () => Promise.reject(new Error('caído')));
    await h.blocklist.refreshNetworkPrefixes(later);
    expect((await h.scoring.decide(h.req({ ip: '203.0.113.5' }))).action).toBe('BLOCK');

    h.blocklist.setPrefixFetcher(async () => ['198.51.100.0/24']);
    await h.blocklist.refreshNetworkPrefixes(later);
    expect((await h.scoring.decide(h.req({ ip: '198.51.100.5' }))).action).toBe('BLOCK');
    expect((await h.scoring.decide(h.req({ ip: '203.0.113.5' }))).action).toBe('ALLOW');
  });
});
