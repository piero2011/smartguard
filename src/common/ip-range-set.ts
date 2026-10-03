import type * as ipaddr from 'ipaddr.js';
import { ParsedIp, parseCidr } from './ip.util';

interface Range<N, T> {
  start: N;
  end: N;
  tag: T;
}

function v4ToInt(a: ipaddr.IPv4): number {
  const [o0 = 0, o1 = 0, o2 = 0, o3 = 0] = a.octets;
  return ((o0 << 24) | (o1 << 16) | (o2 << 8) | o3) >>> 0;
}

function v6ToBig(a: ipaddr.IPv6): bigint {
  let n = 0n;
  for (const b of a.toByteArray()) n = (n << 8n) | BigInt(b);
  return n;
}

/** Ordena por inicio y funde los rangos solapados (un /24 dentro de un /20…): así basta una búsqueda binaria. */
function merge<N extends number | bigint, T>(ranges: Range<N, T>[]): Range<N, T>[] {
  ranges.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  const out: Range<N, T>[] = [];
  for (const r of ranges) {
    const last = out[out.length - 1];
    if (last && r.start <= last.end) {
      if (r.end > last.end) last.end = r.end;
    } else {
      out.push({ ...r });
    }
  }
  return out;
}

function search<N extends number | bigint, T>(ranges: Range<N, T>[], x: N): T | null {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = ranges[mid]!;
    if (x < r.start) hi = mid - 1;
    else if (x > r.end) lo = mid + 1;
    else return r.tag;
  }
  return null;
}

/**
 * Conjunto de CIDRs (IPv4 + IPv6) con etiqueta, para miles de redes: búsqueda binaria O(log n).
 * CidrSet es lineal y sirve para decenas de redes; los rangos de un proveedor de hosting son ~1000.
 *
 * Se descartan los prefijos demasiado amplios (más cortos que /8 en IPv4 o /16 en IPv6): un dato
 * erróneo de la fuente no debe poder cubrir media Internet.
 */
export class IpRangeSet<T> {
  private v4: Range<number, T>[] = [];
  private v6: Range<bigint, T>[] = [];
  /** CIDRs aceptados */
  readonly size: number;

  constructor(entries: Iterable<{ cidr: string; tag: T }> = []) {
    const v4: Range<number, T>[] = [];
    const v6: Range<bigint, T>[] = [];
    for (const { cidr, tag } of entries) {
      const p = parseCidr(cidr);
      if (!p) continue;
      const bits = p.range[1];
      if (p.version === 4) {
        if (bits < 8) continue;
        const mask = bits === 32 ? 0xffffffff : (~(0xffffffff >>> bits)) >>> 0;
        const start = (v4ToInt(p.range[0] as ipaddr.IPv4) & mask) >>> 0;
        v4.push({ start, end: (start | (~mask >>> 0)) >>> 0, tag });
      } else {
        if (bits < 16) continue;
        const host = (1n << BigInt(128 - bits)) - 1n;
        const start = v6ToBig(p.range[0] as ipaddr.IPv6) & ~host;
        v6.push({ start, end: start | host, tag });
      }
    }
    this.size = v4.length + v6.length;
    this.v4 = merge(v4);
    this.v6 = merge(v6);
  }

  /** Etiqueta de la red que contiene la IP, o null. */
  find(ip: ParsedIp): T | null {
    if (ip.version === 4) return this.v4.length ? search(this.v4, v4ToInt(ip.addr as ipaddr.IPv4)) : null;
    return this.v6.length ? search(this.v6, v6ToBig(ip.addr as ipaddr.IPv6)) : null;
  }
}
