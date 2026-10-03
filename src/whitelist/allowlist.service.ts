import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { promises as dnsPromises } from 'node:dns';
import { ConfigService } from '../config/config.service';
import { CidrSet, ParsedCidr, ParsedIp, parseCidr, parseIp } from '../common/ip.util';
import { DnsResolver, DomainPattern, domainMatches, fcrdns, parseDomainPattern } from '../common/dns.util';
import { AllowType } from '../common/types';
import { ApiError } from '../common/api-error';
import { ReputationService } from '../reputation/reputation.service';
import { AllowEntry, AllowKind, AllowTarget } from '../reputation/reputation.store';
import { TtlMap } from '../reputation/memory.store';
import { logger } from '../common/logger';

export type ClientAllowType = Exclude<AllowType, 'VERIFIED_BOT'>;
const CLIENT_TYPES: ClientAllowType[] = ['ADMIN_ALLOWLIST', 'SERVICE_ALLOWLIST', 'TRUSTED_NETWORK'];

export interface ParsedAllowValue {
  value: string;
  kind: AllowKind;
  cidr?: ParsedCidr;
  domain?: DomainPattern;
}

/**
 * Normaliza un valor de allowlist: IP/CIDR, dominio exacto, *.dominio o URL de un sitio
 * (https://api.ejemplo.com/ruta → api.ejemplo.com).
 */
export function parseAllowValue(input: string): ParsedAllowValue | null {
  let s = input.trim();
  if (/^https?:\/\//i.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      return null;
    }
    if (s.startsWith('[')) s = s.slice(1, -1); // URL con IPv6 literal
  }
  const c = parseCidr(s);
  if (c) return { value: c.text, kind: 'cidr', cidr: c };
  if (s.includes(':') || /^[\d./]+$/.test(s)) return null; // IP mal formada, no es un dominio
  const d = parseDomainPattern(s);
  return d ? { value: d.text, kind: d.wildcard ? 'wildcard' : 'domain', domain: d } : null;
}

/** Entrada registrada (estática del .env, integrada o dinámica de la API). */
interface RegistryEntry {
  value: string;
  kind: AllowKind;
  target: AllowTarget;
  type: ClientAllowType;
  source: 'env' | 'builtin' | 'dynamic';
  note?: string;
  expiresAt?: number;
  createdAt?: number;
  cidr?: ParsedCidr;
  domain?: DomainPattern;
}

export type MatchReason = 'exact' | 'cidr' | 'domain-resolved' | 'subdomain-verified' | 'domain-pattern' | 'host';

/** Coincidencia devuelta por lookup(): EN QUÉ lista está un valor y por qué. */
export interface AllowMatch {
  list: ClientAllowType | 'ALLOW_HOSTS';
  target: AllowTarget;
  value: string;
  source: 'env' | 'builtin' | 'dynamic';
  matchedBy: MatchReason;
  note?: string;
  expiresAt?: number;
  createdAt?: number;
  detail?: string;
}

export interface LookupResult {
  input: string;
  normalized: string | null;
  kind: AllowKind | null;
  isIp: boolean;
  matches: AllowMatch[];
}

function cidrContains(outer: ParsedCidr, inner: ParsedCidr): boolean {
  if (outer.version !== inner.version || inner.range[1] < outer.range[1]) return false;
  return (inner.range[0] as { match(r: [unknown, number]): boolean }).match(outer.range as [unknown, number]);
}

/**
 * Allowlist (puntos 32 y 33). NUNCA por User-Agent. Admite:
 *
 *  Clientes (quién hace la petición):
 *   - IP / CIDR (IPv4/IPv6)                       203.0.113.36, 2001:db8::/48
 *   - Dominio exacto → se resuelve a sus IPs       app.customily.com   (A/AAAA, refresco cada 10 min)
 *   - Subdominios    → verificación FCrDNS         *.customily.com     (PTR + resolución directa)
 *  Hosts destino (target=host): sitios/subdominios propios que SmartGuard no debe puntuar
 *   (APIs internas, paneles). Admite URL: https://api.ejemplo.com/x → api.ejemplo.com
 *
 * lookup(valor) responde "¿está ya en alguna lista? ¿en cuál y por qué?" y add() rechaza duplicados
 * (409 ALREADY_ALLOWLISTED / ALREADY_COVERED) indicando la lista.
 *
 * Coste: IP/CIDR y dominios exactos se comprueban en memoria (sin DNS por petición).
 * Los *.dominio requieren un PTR por IP nueva: solo se consulta (asíncrono, cacheado 6–24 h) cuando
 * la petición ya tiene señales sospechosas, nunca para tráfico normal.
 */
@Injectable()
export class AllowlistService implements OnModuleInit, OnModuleDestroy {
  private registry: RegistryEntry[] = [];
  private cidrSets: Record<ClientAllowType, CidrSet> = this.emptySets();
  private dynamic: AllowEntry[] = [];
  /** IP resuelta de un dominio exacto → tipo */
  private resolved = new Map<string, ClientAllowType>();
  /** dominio exacto → IPs resueltas */
  private resolvedView: Record<string, string[]> = {};
  /** IP → "TIPO|hostname" verificado por FCrDNS, o "none"/"error" */
  private fcCache = new TtlMap<string>(50_000);
  private inflight = new Set<string>();
  private queue: string[] = [];
  private active = 0;
  private resolver: DnsResolver;
  private timers: NodeJS.Timeout[] = [];

  constructor(
    private readonly config: ConfigService,
    private readonly reputation: ReputationService,
  ) {
    this.resolver = new dnsPromises.Resolver({ timeout: config.env.dnsTimeoutMs, tries: 1 });
    this.compile([]);
  }

  /** Solo tests */
  setResolver(r: DnsResolver): void {
    this.resolver = r;
  }

  async onModuleInit(): Promise<void> {
    await this.refresh();
    const t1 = setInterval(() => void this.refresh(), 30_000);
    const t2 = setInterval(() => void this.resolveDomains(), this.config.env.allowDomainRefreshSec * 1000);
    t1.unref();
    t2.unref();
    this.timers.push(t1, t2);
  }

  onModuleDestroy(): void {
    for (const t of this.timers) clearInterval(t);
  }

  private emptySets(): Record<ClientAllowType, CidrSet> {
    return { ADMIN_ALLOWLIST: new CidrSet(), SERVICE_ALLOWLIST: new CidrSet(), TRUSTED_NETWORK: new CidrSet() };
  }

  private compile(dynamic: AllowEntry[]): void {
    const env = this.config.env;
    const reg: RegistryEntry[] = [];
    const push = (raw: string, type: ClientAllowType, target: AllowTarget, source: RegistryEntry['source'], extra: Partial<RegistryEntry> = {}) => {
      const p = parseAllowValue(raw);
      if (!p || (target === 'host' && p.kind === 'cidr')) {
        logger.warn(`Entrada de allowlist inválida (${source}): "${raw}" (ignorada)`, 'Allowlist');
        return;
      }
      reg.push({ value: p.value, kind: p.kind, target, type, source, cidr: p.cidr, domain: p.domain, ...extra });
    };
    push('127.0.0.0/8', 'TRUSTED_NETWORK', 'client', 'builtin');
    push('::1/128', 'TRUSTED_NETWORK', 'client', 'builtin');
    for (const v of env.adminAllowlist) push(v, 'ADMIN_ALLOWLIST', 'client', 'env');
    for (const v of env.serviceAllowlist) push(v, 'SERVICE_ALLOWLIST', 'client', 'env');
    for (const v of env.trustedNetworks) push(v, 'TRUSTED_NETWORK', 'client', 'env');
    for (const v of env.allowHosts) push(v, 'SERVICE_ALLOWLIST', 'host', 'env');
    for (const e of dynamic) {
      if (e.type === 'VERIFIED_BOT') continue;
      push(e.value, e.type, e.target ?? 'client', 'dynamic', { note: e.note, expiresAt: e.expiresAt, createdAt: e.createdAt });
    }
    const sets = this.emptySets();
    for (const r of reg) if (r.target === 'client' && r.cidr) sets[r.type].add(r.cidr.text);
    this.registry = reg;
    this.cidrSets = sets;
  }

  private get exact(): RegistryEntry[] {
    return this.registry.filter((r) => r.target === 'client' && r.kind === 'domain');
  }
  private get wildcard(): RegistryEntry[] {
    return this.registry.filter((r) => r.target === 'client' && r.kind === 'wildcard');
  }
  private get hosts(): RegistryEntry[] {
    return this.registry.filter((r) => r.target === 'host');
  }

  async refresh(): Promise<void> {
    try {
      const entries = await this.reputation.call((s) => s.listAllow());
      const changed = JSON.stringify(entries) !== JSON.stringify(this.dynamic);
      this.dynamic = entries;
      this.compile(entries);
      if (changed || this.resolved.size === 0) await this.resolveDomains();
    } catch (e) {
      logger.warn(`No se pudo refrescar la allowlist: ${(e as Error).message}`, 'Allowlist');
    }
  }

  /** Resuelve A/AAAA de los dominios exactos (asíncrono, nunca en el camino de la decisión). */
  async resolveDomains(): Promise<void> {
    const map = new Map<string, ClientAllowType>();
    const view: Record<string, string[]> = {};
    const exact = this.exact;
    await Promise.all(
      exact.map(async ({ domain, type, value }) => {
        const ips = new Set<string>();
        for (const fn of [this.resolver.resolve4.bind(this.resolver), this.resolver.resolve6.bind(this.resolver)]) {
          try {
            for (const a of await fn(domain!.domain)) {
              const p = parseIp(a);
              if (p) ips.add(p.address);
            }
          } catch {
            /* sin registros de ese tipo */
          }
        }
        view[value] = [...ips];
        for (const ip of ips) if (!map.has(ip)) map.set(ip, type);
        if (ips.size === 0) logger.warn(`Dominio de allowlist sin IPs: ${value}`, 'Allowlist');
      }),
    );
    // Si la resolución falla por completo no se vacía la lista anterior
    if (map.size > 0 || exact.length === 0) {
      this.resolved = map;
      this.resolvedView = view;
    }
  }

  /**
   * Tipo de allowlist del cliente, o null. Síncrono y sin DNS.
   * lookup=true: si hay patrones *.dominio y la IP no está en caché, encola su verificación FCrDNS.
   */
  classify(ip: ParsedIp, opts: { lookup?: boolean } = {}): ClientAllowType | null {
    for (const t of CLIENT_TYPES) if (this.cidrSets[t].contains(ip)) return t;
    const r = this.resolved.get(ip.address);
    if (r) return r;
    if (this.wildcard.length > 0) {
      const cached = this.fcCache.get(ip.address);
      if (cached && cached.includes('|')) return cached.split('|')[0] as ClientAllowType;
      if (cached === undefined && opts.lookup) this.enqueue(ip.address);
    }
    return null;
  }

  /** ¿El host destino está exento de SmartGuard? */
  hostAllowed(host: string): boolean {
    if (!host) return false;
    return this.hosts.some((h) => domainMatches(host, h.domain!));
  }

  /** ¿Está ya este valor (IP, CIDR, dominio, *.dominio, URL) en alguna lista? ¿En cuál y por qué? */
  lookup(input: string): LookupResult {
    const p = parseAllowValue(input);
    if (!p) return { input, normalized: null, kind: null, isIp: false, matches: [] };
    const matches: AllowMatch[] = [];
    const add = (r: RegistryEntry, matchedBy: MatchReason, detail?: string) =>
      matches.push({
        list: r.target === 'host' ? 'ALLOW_HOSTS' : r.type,
        target: r.target,
        value: r.value,
        source: r.source,
        matchedBy,
        note: r.note,
        expiresAt: r.expiresAt,
        createdAt: r.createdAt,
        detail,
      });
    const isIp = p.kind === 'cidr' && p.cidr!.range[1] === (p.cidr!.version === 4 ? 32 : 128);

    if (p.kind === 'cidr') {
      const ip = isIp ? parseIp(p.cidr!.range[0].toString()) : null;
      for (const r of this.registry) {
        if (r.target !== 'client') continue;
        if (r.cidr) {
          if (r.value === p.value) add(r, 'exact');
          else if (cidrContains(r.cidr, p.cidr!)) add(r, 'cidr');
        } else if (ip && r.kind === 'domain' && (this.resolvedView[r.value] ?? []).includes(ip.address)) {
          add(r, 'domain-resolved', ip.address);
        } else if (ip && r.kind === 'wildcard') {
          const cached = this.fcCache.get(ip.address);
          const host = cached && cached.includes('|') ? cached.split('|')[1]! : '';
          if (host && domainMatches(host, r.domain!)) add(r, 'subdomain-verified', host);
        }
      }
    } else {
      const d = p.domain!;
      for (const r of this.registry) {
        if (r.kind === 'cidr') continue;
        if (r.value === p.value) add(r, r.target === 'host' ? 'host' : 'exact');
        else if (r.domain!.wildcard && domainMatches(d.domain, r.domain!)) add(r, r.target === 'host' ? 'host' : 'domain-pattern');
      }
    }
    return { input, normalized: p.value, kind: p.kind, isIp, matches };
  }

  private enqueue(ip: string): void {
    if (this.inflight.has(ip) || this.queue.length >= 2000) return;
    this.inflight.add(ip);
    this.queue.push(ip);
    this.pump();
  }

  private pump(): void {
    while (this.active < this.config.env.dnsConcurrency && this.queue.length > 0) {
      const ip = this.queue.shift()!;
      this.active++;
      void this.verifyWildcard(ip).finally(() => {
        this.active--;
        this.inflight.delete(ip);
        this.pump();
      });
    }
  }

  private async verifyWildcard(ip: string): Promise<void> {
    const env = this.config.env;
    const wc = this.wildcard;
    try {
      const host = await fcrdns(this.resolver, ip, wc.map((w) => w.domain!));
      const match = host ? wc.find((w) => domainMatches(host, w.domain!)) : undefined;
      if (match && host) {
        this.fcCache.set(ip, `${match.type}|${host}`, env.dnsPositiveTtlSec * 1000);
        logger.log(`Allowlist por subdominio: ${ip} verificado como ${host} (${match.type})`, 'Allowlist');
      } else {
        this.fcCache.set(ip, 'none', env.dnsNegativeTtlSec * 1000);
      }
    } catch {
      this.fcCache.set(ip, 'error', 5 * 60_000);
    }
  }

  /** Espera a que termine la cola FCrDNS (tests). */
  async drain(): Promise<void> {
    while (this.active > 0 || this.queue.length > 0) await new Promise((r) => setTimeout(r, 5));
  }

  /** Añade una entrada. Rechaza duplicados indicando en qué lista está ya (409). */
  async add(value: string, type: ClientAllowType, target: AllowTarget, note: string, ttlSec?: number): Promise<AllowEntry> {
    const p = parseAllowValue(value);
    if (!p) throw new ApiError(400, 'INVALID_VALUE', `Invalid value "${value}" (use IP, CIDR, domain, *.domain or site URL)`, { value });
    if (target === 'host' && p.kind === 'cidr') {
      throw new ApiError(400, 'HOST_REQUIRES_DOMAIN', 'An exempt destination host must be a domain, *.domain or site URL, not an IP', { value: p.value });
    }
    const existing = this.lookup(p.value).matches.filter((m) => m.target === target);
    const exact = existing.filter((m) => m.matchedBy === 'exact' || (target === 'host' && m.value === p.value));
    if (exact.length > 0) {
      throw new ApiError(409, 'ALREADY_ALLOWLISTED', `${p.value} is already in ${exact.map((m) => `${m.list} (${m.source})`).join(', ')}`, {
        value: p.value,
        matches: exact,
      });
    }
    if (existing.length > 0) {
      throw new ApiError(409, 'ALREADY_COVERED', `${p.value} is already covered by ${existing.map((m) => `${m.value} in ${m.list} (${m.source})`).join(', ')}`, {
        value: p.value,
        matches: existing,
      });
    }
    const entry: AllowEntry = {
      value: p.value,
      kind: p.kind,
      target,
      type,
      note: note.slice(0, 200),
      createdAt: Date.now(),
      expiresAt: ttlSec ? Date.now() + ttlSec * 1000 : undefined,
    };
    await this.reputation.call((s) => s.setAllow(entry));
    // Al permitir un subdominio, olvidar resultados FCrDNS negativos previos
    if (p.kind === 'wildcard') this.fcCache = new TtlMap<string>(50_000);
    await this.refresh();
    return entry;
  }

  /** Quita una entrada dinámica. Las del .env no se pueden quitar desde la API (409 STATIC_ENTRY). */
  async remove(value: string): Promise<boolean> {
    const p = parseAllowValue(value);
    if (!p) throw new ApiError(400, 'INVALID_VALUE', `Invalid value "${value}"`, { value });
    const statics = this.registry.filter((r) => r.value === p.value && r.source !== 'dynamic');
    const ok = await this.reputation.call((s) => s.deleteAllow(p.value));
    if (!ok && statics.length > 0) {
      throw new ApiError(409, 'STATIC_ENTRY', `${p.value} is defined in ${statics.map((s) => s.source === 'env' ? '.env' : 'built-in').join(', ')}; edit it there`, {
        value: p.value,
        lists: statics.map((s) => (s.target === 'host' ? 'ALLOW_HOSTS' : s.type)),
      });
    }
    if (!ok) throw new ApiError(404, 'NOT_IN_ALLOWLIST', `${p.value} is not in the allowlist`, { value: p.value });
    if (p.kind === 'wildcard') this.fcCache = new TtlMap<string>(50_000);
    await this.refresh();
    return true;
  }

  list(): { static: Record<string, string[]>; dynamic: AllowEntry[]; resolvedDomains: Record<string, string[]> } {
    const env = this.config.env;
    return {
      static: {
        ADMIN_ALLOWLIST: env.adminAllowlist,
        SERVICE_ALLOWLIST: env.serviceAllowlist,
        TRUSTED_NETWORK: ['127.0.0.0/8', '::1/128', ...env.trustedNetworks],
        ALLOW_HOSTS: env.allowHosts,
      },
      dynamic: this.dynamic,
      resolvedDomains: this.resolvedView,
    };
  }
}
