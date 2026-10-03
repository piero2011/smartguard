import { Injectable, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { NginxSitesService } from '../admin/nginx-sites.service';
import { HOST_FIELD_PREFIX, TopMaps } from '../reputation/reputation.store';
import { ConfigService } from '../config/config.service';
import { ReputationService } from '../reputation/reputation.service';
import { SecurityEvent } from '../common/types';
import { logger } from '../common/logger';

/**
 * Contadores agregados EN MEMORIA y volcados a Redis cada 10 s en un único pipeline
 * (punto 94: minimizar operaciones Redis). También bufferiza los eventos de seguridad
 * hacia el stream smartguard:events.
 */
@Injectable()
export class StatsService implements OnModuleInit, OnModuleDestroy {
  private fields: Record<string, number> = {};
  private ips = new Set<string>();
  private topPaths = new Map<string, number>();
  private topIps = new Map<string, number>();
  private topRules = new Map<string, number>();
  /** los mismos "top", por sitio */
  private hostTops = new Map<string, TopMaps>();
  /** IPs vistas en cada sitio */
  private hostIps = new Map<string, Set<string>>();
  /** sitios vistos en este volcado (acotado: el Host lo elige quien hace la petición) */
  private hosts = new Set<string>();
  /** dominios de los sitios protegidos según Nginx; null = no se pudo leer (se acepta cualquiera, acotado) */
  private knownHosts: Set<string> | null = null;
  private events: SecurityEvent[] = [];
  private minute = currentMinute();
  private timer: NodeJS.Timeout | null = null;
  private sitesTimer: NodeJS.Timeout | null = null;
  static readonly MAX_HOSTS_BUFFER = 64;
  /**
   * Últimas peticiones evaluadas por sitio, SOLO en memoria (se pierden al reiniciar; no van a Redis).
   * Una lista por sitio para que el más visitado no desplace a los demás; "" = host no reconocido.
   */
  private recent = new Map<string, Ring<RecentRequest>>();
  static readonly RECENT_PER_SITE = 300;
  private recentSeq = 0;
  static readonly MAX_IPS_BUFFER = 20_000;
  static readonly MAX_EVENTS_BUFFER = 5_000;
  static readonly MAX_TOP_BUFFER = 5_000;

  constructor(
    private readonly config: ConfigService,
    private readonly reputation: ReputationService,
    @Optional() private readonly sites?: NginxSitesService,
  ) {}

  onModuleInit(): void {
    this.timer = setInterval(() => void this.flush(), 10_000);
    this.timer.unref();
    void this.refreshKnownHosts();
    this.sitesTimer = setInterval(() => void this.refreshKnownHosts(), 60_000);
    this.sitesTimer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    if (this.sitesTimer) clearInterval(this.sitesTimer);
    await this.flush();
  }

  private async refreshKnownHosts(): Promise<void> {
    try {
      const r = await this.sites?.list();
      const names = (r?.items ?? []).filter((s) => s.status !== 'none').flatMap((s) => s.names);
      this.knownHosts = r?.readable && names.length ? new Set(names) : null;
    } catch {
      this.knownHosts = null;
    }
  }

  /**
   * Host por el que separar las cifras, o null. Solo sitios protegidos conocidos; si no se conocen
   * (vhosts ilegibles), cualquier host con forma de dominio hasta MAX_HOSTS_BUFFER por volcado.
   */
  siteName(host: string | undefined): string | null {
    const h = (host ?? '').toLowerCase().replace(/:\d+$/, '');
    if (!/^[a-z0-9]([a-z0-9.-]{0,98}[a-z0-9])?$/.test(h)) return null;
    if (this.knownHosts) return this.knownHosts.has(h) ? h : null;
    if (!this.hosts.has(h) && this.hosts.size >= StatsService.MAX_HOSTS_BUFFER) return null;
    return h;
  }

  /** Suma al contador global y, si se indica un host válido, también al de ese sitio. */
  incr(field: string, by = 1, host?: string): void {
    this.rollIfNeeded();
    this.fields[field] = (this.fields[field] ?? 0) + by;
    const site = this.siteName(host);
    if (site) {
      this.hosts.add(site);
      const f = `${HOST_FIELD_PREFIX}${site}:${field}`;
      this.fields[f] = (this.fields[f] ?? 0) + by;
    }
  }

  seenIp(ipKey: string, host?: string): void {
    if (this.ips.size >= StatsService.MAX_IPS_BUFFER) return;
    this.ips.add(ipKey);
    const site = this.siteName(host);
    if (site) {
      this.hosts.add(site);
      let set = this.hostIps.get(site);
      if (!set) this.hostIps.set(site, (set = new Set()));
      set.add(ipKey);
    }
  }

  attack(ipKey: string, path: string, ruleIds: string[], points: number, host?: string): void {
    const targets: TopMaps[] = [{ ips: this.topIps, paths: this.topPaths, rules: this.topRules }];
    const site = this.siteName(host);
    if (site) {
      this.hosts.add(site);
      let m = this.hostTops.get(site);
      if (!m) this.hostTops.set(site, (m = { ips: new Map(), paths: new Map(), rules: new Map() }));
      targets.push(m);
    }
    for (const t of targets) {
      bump(t.ips, ipKey, points);
      bump(t.paths, path, 1);
      for (const r of ruleIds) bump(t.rules, r, 1);
    }
  }

  /** Anota una petición evaluada (permitida o no) en la lista de tráfico reciente de su sitio. */
  request(r: RecentRequest): void {
    const site = this.siteName(r.host) ?? '';
    let ring = this.recent.get(site);
    if (!ring) {
      if (this.recent.size > StatsService.MAX_HOSTS_BUFFER) return;
      this.recent.set(site, (ring = new Ring(StatsService.RECENT_PER_SITE)));
    }
    ring.push({ ...r, n: ++this.recentSeq, host: site || r.host.slice(0, 100), path: r.path.slice(0, 200), userAgent: r.userAgent.slice(0, 200) });
  }

  /** Tráfico reciente, de más nuevo a más antiguo. `hosts`: solo esos dominios; vacío = todos. */
  recentRequests(hosts: string[] = []): RecentRequest[] {
    const rings = hosts.length ? hosts.map((h) => this.recent.get(h)) : [...this.recent.values()];
    return rings.flatMap((r) => r?.all() ?? []).sort((a, b) => b.t - a.t || (b.n ?? 0) - (a.n ?? 0));
  }

  event(e: SecurityEvent): void {
    if (this.events.length < StatsService.MAX_EVENTS_BUFFER) this.events.push(e);
  }

  private rollIfNeeded(): void {
    const m = currentMinute();
    if (m !== this.minute) void this.flush();
  }

  async flush(): Promise<void> {
    const minute = this.minute;
    const fields = this.fields;
    const ips = [...this.ips];
    const top = { hour: Math.floor((minute * 60) / 3600), paths: this.topPaths, ips: this.topIps, rules: this.topRules, hosts: this.hostTops, hostIps: new Map([...this.hostIps].map(([h, set]): [string, string[]] => [h, [...set]])) };
    const events = this.events;
    this.minute = currentMinute();
    this.fields = {};
    this.ips = new Set();
    this.topPaths = new Map();
    this.topIps = new Map();
    this.topRules = new Map();
    this.hostTops = new Map();
    this.hostIps = new Map();
    this.hosts = new Set();
    this.events = [];
    try {
      if (Object.keys(fields).length || ips.length || top.paths.size || top.hostIps.size) {
        await this.reputation.call((s) => s.flushStats(minute, fields, ips, top));
      }
      if (events.length) await this.reputation.call((s) => s.pushEvents(events, this.config.env.eventsStreamMaxLen));
    } catch (e) {
      logger.warn(`No se pudieron volcar estadísticas: ${(e as Error).message}`, 'Stats');
    }
  }
}

/** Una petición evaluada por SmartGuard (también las permitidas), para la vista "Tráfico" del panel. */
export interface RecentRequest {
  t: number;
  ip: string;
  ipKey: string;
  host: string;
  method: string;
  /** ruta SIN query string */
  path: string;
  userAgent: string;
  /** ALLOW, OBSERVE, BLOCK… (WOULD_* en AUDIT) */
  action: string;
  country?: string;
  /** orden de llegada: desempata peticiones del mismo milisegundo */
  n?: number;
}

/** Lista circular de tamaño fijo: guarda las últimas `size` entradas sin reservar memoria nueva. */
class Ring<T> {
  private readonly items: T[] = [];
  private next = 0;
  constructor(private readonly size: number) {}
  push(v: T): void {
    if (this.items.length < this.size) this.items.push(v);
    else this.items[this.next] = v;
    this.next = (this.next + 1) % this.size;
  }
  all(): T[] {
    return this.items;
  }
}

function bump(m: Map<string, number>, k: string, by: number): void {
  if (m.size >= StatsService.MAX_TOP_BUFFER && !m.has(k)) return;
  m.set(k, (m.get(k) ?? 0) + by);
}

export function currentMinute(now = Date.now()): number {
  return Math.floor(now / 60_000);
}
