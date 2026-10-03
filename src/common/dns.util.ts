import { parseIp } from './ip.util';

export interface DnsResolver {
  reverse(ip: string): Promise<string[]>;
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
}

/**
 * Entrada de dominio para allowlists:
 *   "app.customily.com"   → exacto (se resuelve a sus IPs)
 *   "*.customily.com"     → cualquier subdominio (y el propio dominio), verificado por FCrDNS
 */
export interface DomainPattern {
  text: string;
  domain: string;
  wildcard: boolean;
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

export function parseDomainPattern(input: string): DomainPattern | null {
  let s = input.trim().toLowerCase();
  if (!s || s.length > 255) return null;
  let wildcard = false;
  if (s.startsWith('*.')) {
    wildcard = true;
    s = s.slice(2);
  } else if (s.startsWith('.')) {
    wildcard = true;
    s = s.slice(1);
  }
  if (s.endsWith('.')) s = s.slice(0, -1);
  const labels = s.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return null;
  if (/^\d+$/.test(labels[labels.length - 1]!)) return null; // parece IP
  return { text: wildcard ? `*.${s}` : s, domain: s, wildcard };
}

/** ¿El hostname coincide con el patrón? (wildcard: el dominio y todos sus subdominios) */
export function domainMatches(host: string, p: DomainPattern): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return h === p.domain || (p.wildcard && h.endsWith(`.${p.domain}`));
}

/**
 * DNS inverso confirmado (FCrDNS): IP → PTR → el hostname debe pertenecer a alguno de los dominios →
 * A/AAAA del hostname debe devolver la MISMA IP. Devuelve el hostname verificado o null.
 * Un PTR por sí solo no prueba nada (lo controla el dueño de la IP), por eso la resolución directa.
 */
export async function fcrdns(resolver: DnsResolver, ip: string, patterns: DomainPattern[]): Promise<string | null> {
  const parsed = parseIp(ip);
  if (!parsed || patterns.length === 0) return null;
  let names: string[];
  try {
    names = await resolver.reverse(parsed.address);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOTFOUND' || code === 'ENODATA') return null;
    throw e;
  }
  for (const raw of names.slice(0, 5)) {
    const host = raw.toLowerCase().replace(/\.$/, '');
    if (!patterns.some((p) => domainMatches(host, p))) continue;
    let addrs: string[] = [];
    try {
      addrs = parsed.version === 4 ? await resolver.resolve4(host) : await resolver.resolve6(host);
    } catch {
      continue;
    }
    if (addrs.some((a) => parseIp(a)?.address === parsed.address)) return host;
  }
  return null;
}
