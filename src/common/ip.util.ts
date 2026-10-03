import * as ipaddr from 'ipaddr.js';

/**
 * Utilidades IP/CIDR (IPv4 + IPv6) basadas en ipaddr.js.
 * Nunca se asume IPv4. Las IPv4-mapped IPv6 (::ffff:1.2.3.4) se convierten a IPv4.
 */

export interface ParsedIp {
  /** forma canónica: IPv4 "1.2.3.4", IPv6 comprimida "2001:db8::1" */
  address: string;
  version: 4 | 6;
  addr: ipaddr.IPv4 | ipaddr.IPv6;
}

const MAX_IP_LEN = 64;

export function parseIp(input: string | null | undefined): ParsedIp | null {
  if (!input) return null;
  const s = input.trim();
  if (s.length === 0 || s.length > MAX_IP_LEN) return null;
  // Rechaza zonas IPv6 ("fe80::1%eth0") y cualquier carácter raro antes de parsear.
  if (!/^[0-9a-fA-F:.]+$/.test(s)) return null;
  if (!ipaddr.isValid(s)) return null;
  let addr: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    addr = ipaddr.parse(s);
  } catch {
    return null;
  }
  if (addr.kind() === 'ipv6' && (addr as ipaddr.IPv6).isIPv4MappedAddress()) {
    addr = (addr as ipaddr.IPv6).toIPv4Address();
  }
  // ipaddr.isValid acepta formas IPv4 "clásicas" raras (octal, 1 parte). Exigimos 4 octetos decimales.
  if (addr.kind() === 'ipv4' && !/^\d{1,3}(\.\d{1,3}){3}$/.test(s) && !s.includes(':')) return null;
  return {
    address: addr.toString(),
    version: addr.kind() === 'ipv4' ? 4 : 6,
    addr,
  };
}

/**
 * Clave de reputación. IPv4 → la IP. IPv6 → el prefijo (por defecto /64),
 * porque un único cliente IPv6 suele disponer de un /64 completo y puede rotar direcciones.
 */
export function ipKey(ip: ParsedIp, v6Prefix: number): string {
  if (ip.version === 4) return ip.address;
  const prefix = Math.min(128, Math.max(32, v6Prefix));
  if (prefix === 128) return ip.address;
  const bytes = (ip.addr as ipaddr.IPv6).toByteArray();
  for (let bit = prefix; bit < 128; bit++) {
    const byte = bit >> 3;
    bytes[byte] = bytes[byte]! & ~(0x80 >> (bit & 7));
  }
  return `${ipaddr.fromByteArray(bytes).toString()}/${prefix}`;
}

export interface ParsedCidr {
  text: string;
  version: 4 | 6;
  range: [ipaddr.IPv4 | ipaddr.IPv6, number];
}

export function parseCidr(input: string): ParsedCidr | null {
  const s = input.trim();
  if (!s || s.length > 64 || !/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(s)) return null;
  try {
    if (!s.includes('/')) {
      const ip = parseIp(s);
      if (!ip) return null;
      const bits = ip.version === 4 ? 32 : 128;
      return { text: `${ip.address}/${bits}`, version: ip.version, range: [ip.addr, bits] };
    }
    const range = ipaddr.parseCIDR(s);
    const version = range[0].kind() === 'ipv4' ? 4 : 6;
    const max = version === 4 ? 32 : 128;
    if (range[1] < 0 || range[1] > max) return null;
    return { text: `${range[0].toString()}/${range[1]}`, version, range };
  } catch {
    return null;
  }
}

/** Conjunto de CIDRs para comprobar pertenencia. Lineal: pensado para decenas/centenas de redes. */
export class CidrSet {
  private v4: [ipaddr.IPv4, number][] = [];
  private v6: [ipaddr.IPv6, number][] = [];
  readonly entries: string[] = [];

  constructor(cidrs: Iterable<string> = [], onInvalid?: (value: string) => void) {
    for (const c of cidrs) this.add(c, onInvalid);
  }

  add(cidr: string, onInvalid?: (value: string) => void): boolean {
    const parsed = parseCidr(cidr);
    if (!parsed) {
      onInvalid?.(cidr);
      return false;
    }
    if (parsed.version === 4) this.v4.push(parsed.range as [ipaddr.IPv4, number]);
    else this.v6.push(parsed.range as [ipaddr.IPv6, number]);
    this.entries.push(parsed.text);
    return true;
  }

  get size(): number {
    return this.entries.length;
  }

  contains(ip: ParsedIp | null): boolean {
    if (!ip) return false;
    if (ip.version === 4) {
      const a = ip.addr as ipaddr.IPv4;
      for (const r of this.v4) if (a.match(r)) return true;
    } else {
      const a = ip.addr as ipaddr.IPv6;
      for (const r of this.v6) if (a.match(r)) return true;
    }
    return false;
  }
}

/** IPs que jamás deben ir a un firewall ni a Cloudflare (loopback, privadas, reservadas). */
export function isPublicUnicast(ip: ParsedIp): boolean {
  const range = ip.addr.range();
  return range === 'unicast';
}

/** Valida estrictamente un token IP/CIDR antes de pasarlo a un proceso externo (nft). */
export function isSafeNftToken(value: string): boolean {
  return /^[0-9a-f:.]{2,45}(\/\d{1,3})?$/.test(value);
}
