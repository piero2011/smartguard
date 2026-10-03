import { CidrSet, ipKey, isPublicUnicast, isSafeNftToken, parseCidr, parseIp } from '../../src/common/ip.util';
import { analyzeUri, normalizeHost, parseDuration, redactQuery } from '../../src/common/uri.util';

describe('IP utils (IPv4 + IPv6)', () => {
  it('parsea IPv4 e IPv6 y normaliza', () => {
    expect(parseIp('1.2.3.4')?.version).toBe(4);
    expect(parseIp('2001:0db8:0000:0000:0000:0000:0000:0001')?.address).toBe('2001:db8::1');
    expect(parseIp('2001:DB8::1')?.address).toBe('2001:db8::1');
  });

  it('convierte IPv4-mapped IPv6 a IPv4', () => {
    const p = parseIp('::ffff:203.0.113.10');
    expect(p?.version).toBe(4);
    expect(p?.address).toBe('203.0.113.10');
  });

  it('rechaza basura, zonas y formas IPv4 raras', () => {
    for (const bad of ['', 'abc', '1.2.3', '999.1.1.1', 'fe80::1%eth0', '1.2.3.4; rm -rf /', '1.2.3.4 } flush ruleset', '0x7f.1', '127.1']) {
      expect(parseIp(bad)).toBeNull();
    }
  });

  it('agrupa IPv6 por /64 y deja IPv4 intacta', () => {
    expect(ipKey(parseIp('2001:db8:1:2:aaaa:bbbb:cccc:dddd')!, 64)).toBe('2001:db8:1:2::/64');
    expect(ipKey(parseIp('2001:db8:1:2::1')!, 64)).toBe('2001:db8:1:2::/64');
    expect(ipKey(parseIp('198.51.100.7')!, 64)).toBe('198.51.100.7');
    expect(ipKey(parseIp('2001:db8::1')!, 128)).toBe('2001:db8::1');
  });

  it('CidrSet funciona con v4 y v6', () => {
    const s = new CidrSet(['173.245.48.0/20', '2606:4700::/32', '10.0.0.1']);
    expect(s.contains(parseIp('173.245.50.1'))).toBe(true);
    expect(s.contains(parseIp('2606:4700:10::1'))).toBe(true);
    expect(s.contains(parseIp('10.0.0.1'))).toBe(true);
    expect(s.contains(parseIp('8.8.8.8'))).toBe(false);
    expect(s.contains(parseIp('2001:db8::1'))).toBe(false);
  });

  it('valida CIDR', () => {
    expect(parseCidr('10.0.0.0/8')?.text).toBe('10.0.0.0/8');
    expect(parseCidr('10.0.0.0/33')).toBeNull();
    expect(parseCidr('2001:db8::/129')).toBeNull();
    expect(parseCidr('nope')).toBeNull();
  });

  it('solo tokens seguros llegan a nft', () => {
    expect(isSafeNftToken('198.51.100.7')).toBe(true);
    expect(isSafeNftToken('2001:db8:1:2::/64')).toBe(true);
    expect(isSafeNftToken('1.2.3.4 } ; flush ruleset')).toBe(false);
    expect(isSafeNftToken('$(reboot)')).toBe(false);
  });

  it('no considera públicas las IPs privadas/loopback', () => {
    expect(isPublicUnicast(parseIp('127.0.0.1')!)).toBe(false);
    expect(isPublicUnicast(parseIp('192.168.1.1')!)).toBe(false);
    expect(isPublicUnicast(parseIp('8.8.8.8')!)).toBe(true);
    expect(isPublicUnicast(parseIp('2606:4700::1')!)).toBe(true);
  });
});

describe('URI utils', () => {
  it('decodifica y resuelve segmentos de punto', () => {
    const a = analyzeUri('/wp-content/%2e%2e/%2e%2e/etc/passwd?x=1');
    expect(a.path).toBe('/etc/passwd');
    expect(a.dotSegments).toBe(true);
    expect(a.query).toBe('x=1');
  });

  it('colapsa barras y convierte backslash', () => {
    expect(analyzeUri('//wp-admin\\\\admin-ajax.php').path).toBe('/wp-admin/admin-ajax.php');
  });

  it('decodifica doble la query (anti-evasión)', () => {
    const a = analyzeUri('/?q=%2527%2520or%25201%253D1');
    expect(a.decodedQuery).toContain("' or 1=1");
  });

  it('marca secuencias % inválidas y bytes nulos sin lanzar', () => {
    const a = analyzeUri('/%E0%A4%A.php?x=%00');
    expect(a.malformed).toBe(true);
    expect(a.nullByte).toBe(true);
  });

  it('trunca URIs gigantes', () => {
    const a = analyzeUri('/' + 'a'.repeat(10_000));
    expect(a.tooLong).toBe(true);
    expect(a.path.length).toBeLessThanOrEqual(2049);
  });

  it('redacta parámetros sensibles', () => {
    const r = redactQuery('action=rp&key=SECRETKEY&login=juan&billing_email=a@b.c&page=2');
    expect(r).not.toContain('SECRETKEY');
    expect(r).not.toContain('a@b.c');
    expect(r).not.toContain('juan');
    expect(r).toContain('page=2');
  });

  it('normaliza Host y rechaza valores peligrosos', () => {
    expect(normalizeHost('Orleansembroidery.COM:443')).toBe('orleansembroidery.com');
    expect(normalizeHost('evil.com\r\nX-Injected: 1')).toBe('');
    expect(normalizeHost('[::1]')).toBe('');
  });

  it('parsea duraciones', () => {
    expect(parseDuration('15m', 0)).toBe(900);
    expect(parseDuration('1h', 0)).toBe(3600);
    expect(parseDuration('2d', 0)).toBe(172800);
    expect(parseDuration('abc', 60)).toBe(60);
  });
});
