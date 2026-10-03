import { Injectable } from '@nestjs/common';
import { promises as dnsPromises } from 'node:dns';
import type * as ipaddr from 'ipaddr.js';
import { ConfigService } from '../config/config.service';
import { CloudflareRangesService } from '../cloudflare/cloudflare-ranges.service';
import { ParsedIp, isPublicUnicast, parseIp } from '../common/ip.util';
import { TtlMap } from '../reputation/memory.store';

/** A quién pertenece una IP: red (ASN), organización y país donde está registrada esa red. */
export interface IpInfo {
  asn: number | null;
  /** Nombre de la red, p. ej. "DIGITALOCEAN-ASN" */
  org: string;
  /** País de registro de la red (ISO 3166-1 alfa-2). No es geolocalización exacta del visitante. */
  country: string;
  prefix: string;
  /** La red es de un proveedor de hosting / centro de datos (servidores, no personas) */
  hosting: boolean;
  cloudflare: boolean;
}

export interface TxtResolver {
  resolveTxt(name: string): Promise<string[][]>;
}

/** Proveedores de hosting/nube conocidos y palabras que delatan una red de servidores. */
const HOSTING_RE =
  /digitalocean|ovh|amazon|aws|google|microsoft|azure|hetzner|linode|akamai|vultr|choopa|contabo|leaseweb|alibaba|tencent|oracle|scaleway|online s\.?a|hostinger|m247|datacamp|cdn77|ionos|godaddy|hostgator|namecheap|rackspace|equinix|cogent|psychz|quadranet|colocrossing|servers?\b|hosting|\bhost\b|cloud|datacenter|data center|\bvps\b|\bcolo/i;

const DAY = 86_400_000;

/**
 * Datos de red de una IP para el panel (nunca en el camino de la decisión): solo se consulta cuando
 * el administrador abre una tabla, con caché de 24 h.
 *
 * Fuente: servicio IP→ASN de Team Cymru por DNS (TXT), sin API key ni cuota:
 *   IPv4  d.c.b.a.origin.asn.cymru.com      → "14061 | 167.99.144.0/20 | US | arin | 2018-04-05"
 *   IPv6  <32 nibbles>.origin6.asn.cymru.com
 *   ASN   AS14061.asn.cymru.com             → "14061 | US | arin | 2012-09-25 | DIGITALOCEAN-ASN - DigitalOcean, LLC, US"
 * Igual que la verificación de bots (FCrDNS), la consulta sale por el resolver DNS del sistema.
 */
@Injectable()
export class IpInfoService {
  private cache = new TtlMap<IpInfo | null>(20_000);
  private asnNames = new TtlMap<string>(5_000);
  private inflight = new Map<string, Promise<IpInfo | null>>();
  private resolver: TxtResolver;

  constructor(
    private readonly config: ConfigService,
    private readonly cfRanges: CloudflareRangesService,
  ) {
    this.resolver = new dnsPromises.Resolver({ timeout: config.env.dnsTimeoutMs, tries: 1 });
  }

  /** Solo tests */
  setResolver(r: TxtResolver): void {
    this.resolver = r;
  }

  /** Datos de varias IPs (en paralelo, con concurrencia limitada). Las no válidas o privadas → null. */
  async lookupMany(ips: string[]): Promise<Record<string, IpInfo | null>> {
    const out: Record<string, IpInfo | null> = {};
    const queue = [...new Set(ips)];
    const worker = async (): Promise<void> => {
      for (let raw = queue.shift(); raw !== undefined; raw = queue.shift()) out[raw] = await this.lookup(raw);
    };
    await Promise.all(Array.from({ length: Math.min(this.config.env.dnsConcurrency * 2, queue.length) }, worker));
    return out;
  }

  async lookup(raw: string): Promise<IpInfo | null> {
    const ip = parseIp(raw);
    if (!ip || !isPublicUnicast(ip)) return null;
    const cached = this.cache.get(ip.address);
    if (cached !== undefined) return cached;
    let p = this.inflight.get(ip.address);
    if (!p) {
      p = this.resolve(ip).finally(() => this.inflight.delete(ip.address));
      this.inflight.set(ip.address, p);
    }
    return p;
  }

  private async resolve(ip: ParsedIp): Promise<IpInfo | null> {
    try {
      const origin = await this.txt(originName(ip));
      // "14061 | 167.99.144.0/20 | US | arin | 2018-04-05" (puede anunciarse desde varios ASN: "13335 14061 | …")
      const [asns = '', prefix = '', country = ''] = origin.split('|').map((s) => s.trim());
      const asn = Number(asns.split(/\s+/)[0]);
      if (!Number.isInteger(asn) || asn <= 0) throw new Error('sin ASN');
      const org = await this.asnName(asn);
      const info: IpInfo = {
        asn,
        org,
        country: /^[A-Z]{2}$/.test(country) ? country : '',
        prefix: /^[0-9a-fA-F:./]{3,49}$/.test(prefix) ? prefix : '',
        hosting: HOSTING_RE.test(org),
        cloudflare: this.cfRanges.isCloudflare(ip),
      };
      this.cache.set(ip.address, info, DAY);
      return info;
    } catch {
      // Sin respuesta (IP sin anunciar, DNS caído…): no reintentar en cada refresco del panel
      this.cache.set(ip.address, null, 10 * 60_000);
      return null;
    }
  }

  private async asnName(asn: number): Promise<string> {
    const key = String(asn);
    const cached = this.asnNames.get(key);
    if (cached !== undefined) return cached;
    let name = '';
    try {
      // "14061 | US | arin | 2012-09-25 | DIGITALOCEAN-ASN - DigitalOcean, LLC, US" → "DigitalOcean, LLC"
      const fields = (await this.txt(`AS${asn}.asn.cymru.com`)).split('|').map((s) => s.trim());
      const full = (fields[4] ?? '').replace(/,\s*[A-Z]{2}$/, '').replace(/[^\x20-\x7e]/g, '');
      name = (full.split(' - ').slice(1).join(' - ') || full).slice(0, 80);
    } catch {
      name = '';
    }
    this.asnNames.set(key, name, name ? 7 * DAY : 10 * 60_000);
    return name;
  }

  private async txt(name: string): Promise<string> {
    const rows = await this.resolver.resolveTxt(name);
    const first = rows[0]?.join('') ?? '';
    if (!first) throw new Error('TXT vacío');
    return first;
  }
}

/** Nombre DNS de Team Cymru para una IP (octetos o nibbles invertidos). */
export function originName(ip: ParsedIp): string {
  if (ip.version === 4) return `${ip.address.split('.').reverse().join('.')}.origin.asn.cymru.com`;
  const nibbles = (ip.addr as ipaddr.IPv6)
    .toByteArray()
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .split('')
    .reverse()
    .join('.');
  return `${nibbles}.origin6.asn.cymru.com`;
}
