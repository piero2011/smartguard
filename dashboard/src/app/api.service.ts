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
  topPaths: { member: string; score: number }[];
  topIps: { member: string; score: number }[];
  topRules: { member: string; score: number }[];
  degraded: boolean;
}

export interface SecurityEvent {
  timestamp: number;
  ip: string;
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
  stats(minutes = 60): Promise<Stats> {
    return this.req('GET', `/admin/stats?minutes=${minutes}`);
  }
  mode(): Promise<{ audit: boolean; mode: string }> {
    return this.req('GET', '/admin/mode');
  }
  setMode(audit: boolean): Promise<{ audit: boolean; mode: string }> {
    return this.req('POST', '/admin/mode', { audit });
  }
  bans(audit: boolean): Promise<{ total: number; items: BanRecord[] }> {
    return this.req('GET', `/admin/bans?audit=${audit}&limit=500`);
  }
  events(limit = 100): Promise<SecurityEvent[]> {
    return this.req('GET', `/admin/events?limit=${limit}`);
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
