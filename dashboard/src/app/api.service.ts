import { HttpClient, HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { I18n } from './i18n';

// ---------------------------------------------------------------------------
// Tipos de la API de SmartGuard
// ---------------------------------------------------------------------------
export type ClientList = 'ADMIN_ALLOWLIST' | 'SERVICE_ALLOWLIST' | 'TRUSTED_NETWORK';

export interface BanRecord {
  ip: string;
  key: string;
  scope: 'ip' | 'fp';
  reason: string;
  score: number;
  reasons: string[];
  createdAt: number;
  expiresAt: number;
  durationSec: number;
  source: string;
  banCount: number;
  audit: boolean;
  firewall: boolean;
}

export interface AllowMatch {
  list: ClientList | 'ALLOW_HOSTS';
  target: 'client' | 'host';
  value: string;
  source: 'env' | 'builtin' | 'dynamic';
  matchedBy: string;
  note?: string;
  expiresAt?: number;
  detail?: string;
}

export interface AllowEntry {
  value: string;
  kind: 'cidr' | 'domain' | 'wildcard';
  target: 'client' | 'host';
  type: ClientList;
  note: string;
  createdAt: number;
  expiresAt?: number;
}

export interface AllowList {
  static: Record<string, string[]>;
  dynamic: AllowEntry[];
  resolvedDomains: Record<string, string[]>;
}

export interface LookupResult {
  input: string;
  normalized: string;
  kind: string;
  isIp: boolean;
  key: string | null;
  isCloudflare: boolean;
  allowlisted: boolean;
  allowlist: AllowMatch[];
  banned: boolean;
  ban: BanRecord | null;
  auditBan: BanRecord | null;
  fingerprintBans: number;
  score: number | null;
}

export interface Stats {
  mode: 'AUDIT' | 'ENFORCE';
  requestsPerMin: number;
  logLinesPerMin: number;
  activeIps5m: number;
  bansActive: number;
  wouldBansActive: number;
  totals: Record<string, number>;
  /** sitios con datos en el periodo */
  hosts: string[];
  /** contadores del periodo de cada sitio protegido, del que más peticiones tiene al que menos */
  sites?: { site: string; totals: Record<string, number> }[];
  /** minutos que agrupa cada punto de `series` */
  stepMinutes: number;
  /** contadores por tramo de tiempo (t = inicio del tramo, en ms), de más antiguo a más reciente */
  series: ({ t: number } & Record<string, number>)[];
  topPaths: { member: string; score: number }[];
  topIps: { member: string; score: number }[];
  topRules: { member: string; score: number }[];
  degraded: boolean;
}

/** Una petición evaluada por SmartGuard (también las permitidas) */
export interface RecentRequest {
  t: number;
  ip: string;
  ipKey: string;
  host: string;
  method: string;
  path: string;
  userAgent: string;
  action: string;
  country?: string;
}

/** Tráfico reciente (en memoria del servicio) e IPs activas en los últimos 5 minutos */
export interface RecentTraffic {
  host: string;
  stored: number;
  activeIps: { ip: string; ipKey: string; country?: string; requests: number; lastSeen: number; lastPath: string; userAgent: string; blocked: number }[];
  items: RecentRequest[];
}

/** Regla creada desde el panel (lo que se envía y lo que devuelve /admin/panel-rules) */
export interface PanelRule {
  id: string;
  name?: string;
  enabled?: boolean;
  target?: 'path' | 'query' | 'uri' | 'ua' | 'method';
  pattern: string;
  /** al enviar: métodos separados por comas; al leer: lista */
  methods?: string | string[];
  score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence?: 'low' | 'medium' | 'high';
  category: string;
  action?: 'score' | 'block' | 'allow';
}

/**
 * Cuerpo que acepta POST /admin/panel-rules: solo los campos editables (una regla leída del servidor
 * trae además flags, phase, ttl… que la API rechazaría) y los métodos como texto separado por comas.
 */
export function panelRuleBody(r: PanelRule): Record<string, unknown> {
  const methods = Array.isArray(r.methods) ? r.methods.filter((m) => m !== 'ANY').join(',') : (r.methods ?? '');
  return {
    id: r.id,
    name: r.name || undefined,
    enabled: r.enabled,
    target: r.target ?? 'path',
    pattern: r.pattern,
    methods: methods || undefined,
    score: r.score,
    severity: r.severity,
    confidence: r.confidence,
    category: r.category,
    action: r.action,
  };
}

/** Regla activa (de los archivos o del panel), tal como la usa el motor */
export interface RuleInfo {
  id: string;
  name: string;
  source: 'panel' | 'file';
  target: 'path' | 'query' | 'uri' | 'ua' | 'method';
  pattern: string;
  score: number;
  severity: string;
  confidence: string;
  category: string;
  action: 'score' | 'block' | 'allow';
}

/** Un sitio de Nginx y lo que SmartGuard hace en él, según los include de su vhost */
export interface NginxSite {
  file: string;
  /** nombre único del sitio aunque tenga varios dominios */
  primary: string;
  names: string[];
  kind: 'php' | 'proxy' | 'static';
  rules: boolean;
  decision: boolean;
  staticLog: boolean;
  status: 'full' | 'partial' | 'none';
  exempt: boolean;
}

export interface NginxSites {
  /** false = el servicio no tiene permiso para leer los vhosts */
  readable: boolean;
  dirs: string[];
  items: NginxSite[];
}

/** Versión instalada y lo que ocupa SmartGuard en el servidor */
export interface SystemInfo {
  version: string;
  deployment?: 'docker' | 'system';
  commit: string;
  node: string;
  uptimeSec: number;
  memory: { rss: number; heapUsed: number };
  disk: { id: string; path: string; bytes: number | null }[];
  diskTotal: number;
  diskScannedAt: number;
  redis: { events: number; eventsMax: number; eventsBytes: number | null; redisUsedBytes: number | null; degraded: boolean } | null;
}

export interface SecurityEvent {
  timestamp: number;
  ip: string;
  /** clave de reputación (en IPv6, su /64): por ella se guardan los bloqueos */
  ipKey?: string;
  host: string;
  method: string;
  uri: string;
  status?: number;
  category: string;
  scoreDelta: number;
  reason: string;
  action?: string;
  country?: string;
  /** 'decision' (auth_request) o 'analyzer' (log de Nginx) */
  source?: string;
  userAgent?: string;
}

/** Bot bloqueado a mano: texto que se busca en el User-Agent */
export interface BlockedBot {
  pattern: string;
  note: string;
  createdAt: number;
  expiresAt?: number;
}

/** Red completa (ASN) bloqueada a mano */
export interface BlockedNetwork {
  asn: number;
  org: string;
  country: string;
  prefixCount: number;
  note: string;
  createdAt: number;
  fetchedAt: number;
}

/** A quién pertenece una IP (red, organización, país de registro de la red) */
export interface IpInfo {
  asn: number | null;
  org: string;
  country: string;
  prefix: string;
  hosting: boolean;
  cloudflare: boolean;
}

export interface Explanation {
  explanation: string;
  ban: BanRecord | null;
  auditBan: BanRecord | null;
}

/** Error de la API normalizado */
export interface ApiErr {
  status: number;
  code: string;
  message: string;
  params: Record<string, unknown>;
}

/**
 * Duración de un bloqueo manual "hasta que se desbloquee". La API exige una duración, así que se
 * envía una muy larga (10 años) y el panel la muestra como permanente.
 */
export const PERMANENT = '3650d';

/** ¿La caducidad está tan lejos (más de 5 años) que es un bloqueo "hasta desbloquear"? */
export function isPermanent(expiresAt: number): boolean {
  return expiresAt - Date.now() > 5 * 365 * 86_400_000;
}

const TOKEN_KEY = 'sg_token';

@Injectable({ providedIn: 'root' })
export class Api {
  private readonly http = inject(HttpClient);
  private readonly i18n = inject(I18n);

  readonly token = signal<string>(this.readToken());

  private readToken(): string {
    try {
      return sessionStorage.getItem(TOKEN_KEY) ?? '';
    } catch {
      return '';
    }
  }

  setToken(t: string): void {
    this.token.set(t.trim());
    try {
      if (t) sessionStorage.setItem(TOKEN_KEY, t.trim());
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* sin almacenamiento */
    }
  }

  private headers(): HttpHeaders {
    return new HttpHeaders({ authorization: `Bearer ${this.token()}` });
  }

  private async req<T>(method: string, url: string, body?: unknown): Promise<T> {
    try {
      return await firstValueFrom(this.http.request<T>(method, url, { body, headers: this.headers() }));
    } catch (e) {
      throw this.normalize(e);
    }
  }

  normalize(e: unknown): ApiErr {
    if (e instanceof HttpErrorResponse) {
      const b = (e.error ?? {}) as Partial<ApiErr> & { message?: string | string[] };
      const code = b.code ?? (e.status === 401 ? 'UNAUTHORIZED' : e.status === 429 ? 'RATE_LIMITED' : e.status === 0 ? 'NETWORK' : 'HTTP');
      const message = Array.isArray(b.message) ? b.message.join('; ') : (b.message ?? e.message);
      return { status: e.status, code, message, params: b.params ?? {} };
    }
    return { status: 0, code: 'NETWORK', message: String(e), params: {} };
  }

  /** Mensaje traducido para un error (incluye EN QUÉ lista está el valor en conflictos 409). */
  describe(err: ApiErr): string {
    const p = err.params;
    const matches = (p['matches'] as AllowMatch[] | undefined) ?? [];
    const lists = matches.length
      ? matches.map((m) => `${this.i18n.t('list.' + m.list)} [${m.value}, ${this.i18n.t('source.' + m.source)}]`).join('; ')
      : ((p['lists'] as string[] | undefined) ?? []).map((l) => this.i18n.t('list.' + l)).join(', ');
    const ban = p['ban'] as BanRecord | undefined;
    const params: Record<string, unknown> = {
      ...p,
      lists,
      until: ban ? this.i18n.date(ban.expiresAt) : '',
      reason: typeof p['reason'] === 'string' ? p['reason'] : (ban?.reason ?? ''),
      status: err.status,
      message: err.message,
    };
    if (err.code === 'NETWORK') return this.i18n.t('err.network');
    const key = `err.${err.code}`;
    const txt = this.i18n.t(key, params);
    return txt === key ? this.i18n.t('err.generic', params) : txt;
  }

  // --- Endpoints --------------------------------------------------------------
  /** `host`: solo las cifras de ese sitio; vacío = la suma de todos los protegidos. */
  /** `range`: fechas (ms) en lugar de "los últimos N minutos"; sin `to`, hasta ahora. */
  stats(minutes = 60, host = '', range: { from?: number; to?: number } = {}): Promise<Stats> {
    const dates = `${range.from === undefined ? '' : `&from=${range.from}`}${range.to === undefined ? '' : `&to=${range.to}`}`;
    return this.req('GET', `/admin/stats?minutes=${minutes}${dates}${host ? `&host=${encodeURIComponent(host)}` : ''}`);
  }
  mode(): Promise<{ audit: boolean; mode: string; deployment?: 'docker' | 'system' }> {
    return this.req('GET', '/admin/mode');
  }
  setMode(audit: boolean): Promise<{ audit: boolean; mode: string }> {
    return this.req('POST', '/admin/mode', { audit });
  }
  bans(audit: boolean, offset = 0, limit = 500): Promise<{ total: number; items: BanRecord[] }> {
    return this.req('GET', `/admin/bans?audit=${audit}&offset=${offset}&limit=${limit}`);
  }
  recent(host = ''): Promise<RecentTraffic> {
    return this.req('GET', `/admin/recent?limit=300${host ? `&host=${encodeURIComponent(host)}` : ''}`);
  }
  rules(): Promise<{ rules: RuleInfo[] }> {
    return this.req('GET', '/admin/rules');
  }
  panelRules(): Promise<{ items: PanelRule[]; max: number }> {
    return this.req('GET', '/admin/panel-rules');
  }
  savePanelRule(rule: PanelRule): Promise<{ rule: PanelRule }> {
    return this.req('POST', '/admin/panel-rules', panelRuleBody(rule));
  }
  deletePanelRule(id: string): Promise<{ removed: boolean }> {
    return this.req('DELETE', `/admin/panel-rules?id=${encodeURIComponent(id)}`);
  }
  /** POST genérico para la importación de una copia (cada entrada va a su endpoint). */
  post(path: string, body: unknown): Promise<unknown> {
    return this.req('POST', path, body);
  }
  sites(): Promise<NginxSites> {
    return this.req('GET', '/admin/sites');
  }
  system(): Promise<SystemInfo> {
    return this.req('GET', '/admin/system');
  }
  events(limit = 100): Promise<SecurityEvent[]> {
    return this.req('GET', `/admin/events?limit=${limit}`);
  }
  /**
   * Una página de eventos; el servidor filtra (tipo, texto, fechas en ms) sobre todos los guardados.
   * Puede traer menos de `limit` con `next` no nulo: quedan eventos por revisar a partir de ese cursor.
   */
  eventsPage(q: { limit: number; cursor?: string; kind?: string; host?: string; q?: string; from?: number; to?: number }): Promise<{ items: SecurityEvent[]; next: string | null }> {
    const p = new URLSearchParams({ limit: String(q.limit) });
    if (q.cursor) p.set('cursor', q.cursor);
    if (q.kind && q.kind !== 'all') p.set('kind', q.kind);
    if (q.host) p.set('host', q.host);
    if (q.q) p.set('q', q.q);
    if (q.from !== undefined) p.set('from', String(q.from));
    if (q.to !== undefined) p.set('to', String(q.to));
    return this.req('GET', `/admin/events/page?${p}`);
  }
  allowlist(): Promise<AllowList> {
    return this.req('GET', '/admin/allow');
  }
  lookup(value: string): Promise<LookupResult> {
    return this.req('GET', `/admin/lookup?value=${encodeURIComponent(value)}`);
  }
  explain(ip: string): Promise<Explanation> {
    return this.req('GET', `/admin/ip/${encodeURIComponent(ip)}`);
  }
  allow(body: { value: string; type?: ClientList; target: 'client' | 'host'; note?: string; ttl?: string }): Promise<{
    entry: AllowEntry;
    unban?: { removed: boolean };
  }> {
    return this.req('POST', '/admin/allow', body);
  }
  unallow(value: string): Promise<{ removed: boolean }> {
    return this.req('DELETE', `/admin/allow/${encodeURIComponent(value)}`);
  }
  ban(body: { ip: string; duration: string; reason?: string }): Promise<BanRecord> {
    return this.req('POST', '/admin/ban', body);
  }
  unban(ip: string, keepScore: boolean): Promise<{ removed: boolean; fingerprintBans: number; reset: boolean }> {
    return this.req('DELETE', `/admin/ban/${encodeURIComponent(ip)}${keepScore ? '?reset=false' : ''}`);
  }
  ipInfo(ips: string[]): Promise<{ items: Record<string, IpInfo | null> }> {
    return this.req('GET', `/admin/ipinfo?ips=${encodeURIComponent(ips.join(','))}`);
  }
  blockedNetworks(): Promise<{ items: BlockedNetwork[] }> {
    return this.req('GET', '/admin/blocked-networks');
  }
  blockNetwork(body: { ip?: string; asn?: number; note?: string }): Promise<BlockedNetwork> {
    return this.req('POST', '/admin/blocked-networks', body);
  }
  unblockNetwork(asn: number): Promise<{ removed: boolean }> {
    return this.req('DELETE', `/admin/blocked-networks?asn=${asn}`);
  }
  blockedBots(): Promise<{ items: BlockedBot[] }> {
    return this.req('GET', '/admin/blocked-bots');
  }
  blockBot(body: { pattern: string; note?: string }): Promise<BlockedBot> {
    return this.req('POST', '/admin/blocked-bots', body);
  }
  unblockBot(pattern: string): Promise<{ removed: boolean }> {
    return this.req('DELETE', `/admin/blocked-bots?pattern=${encodeURIComponent(pattern)}`);
  }
}
