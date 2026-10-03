import { ConfigService } from '../../src/config/config.service';
import { CloudflareRangesService } from '../../src/cloudflare/cloudflare-ranges.service';
import { IpInfoService, TxtResolver, originName } from '../../src/ipinfo/ipinfo.service';
import { parseIp } from '../../src/common/ip.util';
import { testEnv } from '../helpers';

class FakeTxt implements TxtResolver {
  calls: string[] = [];
  records = new Map<string, string>();
  async resolveTxt(name: string): Promise<string[][]> {
    this.calls.push(name);
    const v = this.records.get(name);
    if (!v) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return [[v]];
  }
}

async function make(): Promise<{ svc: IpInfoService; dns: FakeTxt }> {
  const config = new ConfigService(testEnv());
  await config.loadFiles();
  const svc = new IpInfoService(config, new CloudflareRangesService(config));
  const dns = new FakeTxt();
  svc.setResolver(dns);
  dns.records.set('99.151.99.167.origin.asn.cymru.com', '14061 | 167.99.144.0/20 | US | arin | 2017-11-10');
  dns.records.set('AS14061.asn.cymru.com', '14061 | US | arin | 2012-09-25 | DIGITALOCEAN-ASN - DigitalOcean, LLC, US');
  dns.records.set('7.5.232.190.origin.asn.cymru.com', '64500 64501 | 190.232.0.0/16 | PE | lacnic | 2010-01-01');
  dns.records.set('AS64500.asn.cymru.com', '64500 | PE | lacnic | 2010-01-01 | TELEFONICA DEL PERU S.A.A., PE');
  return { svc, dns };
}

describe('IpInfo: a quién pertenece una IP (Team Cymru por DNS)', () => {
  it('nombre DNS: octetos invertidos en IPv4, nibbles invertidos en IPv6', () => {
    expect(originName(parseIp('167.99.151.99')!)).toBe('99.151.99.167.origin.asn.cymru.com');
    expect(originName(parseIp('2001:db8:0:9::a')!)).toBe(
      'a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.9.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com',
    );
  });

  it('red de hosting: organización, país, prefijo y marca hosting', async () => {
    const { svc } = await make();
    expect(await svc.lookup('167.99.151.99')).toEqual({
      asn: 14061,
      org: 'DigitalOcean, LLC',
      country: 'US',
      prefix: '167.99.144.0/20',
      hosting: true,
      cloudflare: false,
    });
  });

  it('operadora (no hosting) y prefijo anunciado por varios ASN: usa el primero', async () => {
    const { svc } = await make();
    expect(await svc.lookup('190.232.5.7')).toMatchObject({ asn: 64500, org: 'TELEFONICA DEL PERU S.A.A.', country: 'PE', hosting: false });
  });

  it('cachea: la segunda consulta no vuelve a preguntar al DNS', async () => {
    const { svc, dns } = await make();
    await svc.lookup('167.99.151.99');
    const n = dns.calls.length;
    await svc.lookup('167.99.151.99');
    expect(dns.calls.length).toBe(n);
  });

  it('IP privada, inválida o sin respuesta → null (sin lanzar)', async () => {
    const { svc, dns } = await make();
    expect(await svc.lookup('10.1.2.3')).toBeNull();
    expect(await svc.lookup('127.0.0.1')).toBeNull();
    expect(await svc.lookup('no-es-una-ip')).toBeNull();
    expect(dns.calls.length).toBe(0);
    expect(await svc.lookup('198.51.100.9')).toBeNull();
  });

  it('lookupMany devuelve una entrada por IP pedida', async () => {
    const { svc } = await make();
    const r = await svc.lookupMany(['167.99.151.99', '190.232.5.7', '10.0.0.1', '167.99.151.99']);
    expect(Object.keys(r).sort()).toEqual(['10.0.0.1', '167.99.151.99', '190.232.5.7']);
    expect(r['167.99.151.99']?.org).toBe('DigitalOcean, LLC');
    expect(r['10.0.0.1']).toBeNull();
  });
});
