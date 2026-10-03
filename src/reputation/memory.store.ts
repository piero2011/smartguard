import { BanRecord, BanScope, SecurityEvent } from '../common/types';
import {
  AllowEntry,
  ApplyInput,
  ApplyResult,
  BlockedBot,
  IpState,
  ReputationStore,
  ScoringParams,
  StatsBucket,
  TopIncrements,
  banIndexMember,
} from './reputation.store';

/** Map con TTL y tamaño máximo (expulsa lo más antiguo). Protege contra abuso de memoria. */
export class TtlMap<V> {
  private m = new Map<string, { v: V; exp: number }>();
  constructor(private readonly max: number) {}

  get(k: string, now = Date.now()): V | undefined {
    const e = this.m.get(k);
    if (!e) return undefined;
    if (e.exp <= now) {
      this.m.delete(k);
      return undefined;
    }
    return e.v;
  }
  ttlMs(k: string, now = Date.now()): number {
    const e = this.m.get(k);
    if (!e) return -2;
    const t = e.exp - now;
    if (t <= 0) {
      this.m.delete(k);
      return -2;
    }
    return t;
  }
  set(k: string, v: V, ttlMs: number, now = Date.now()): void {
    this.m.delete(k);
    this.m.set(k, { v, exp: now + ttlMs });
    if (this.m.size > this.max) {
      const oldest = this.m.keys().next().value;
      if (oldest !== undefined) this.m.delete(oldest);
    }
  }
  delete(k: string): boolean {
    return this.m.delete(k);
  }
  entries(now = Date.now()): [string, V][] {
    const out: [string, V][] = [];
    for (const [k, e] of this.m) if (e.exp > now) out.push([k, e.v]);
    return out;
  }
  get size(): number {
    return this.m.size;
  }
}

interface RepHash {
  s: number;
  g: number;
  t: number;
  wh: number;
  ws: number;
  f: number;
  l: number;
  h: number;
  cc?: string;
}

const DAY = 86_400_000;

/**
 * Implementación en memoria con la MISMA semántica que el script Lua.
 * Se usa en tests y como almacén degradado local cuando el circuito Redis está abierto.
 */
export class MemoryReputationStore implements ReputationStore {
  readonly kind = 'memory' as const;
  private rep = new TtlMap<RepHash>(100_000);
  private fp = new TtlMap<{ s: number; t: number }>(100_000);
  private fpsByIp = new TtlMap<Set<string>>(100_000);
  private bans = new TtlMap<BanRecord>(50_000);
  private reasons = new TtlMap<{ at: number; reason: string }[]>(50_000);
  private recid = new TtlMap<number>(50_000);
  private counters = new TtlMap<number>(100_000);
  private dns = new TtlMap<string>(50_000);
  private allow = new Map<string, AllowEntry>();
  private blockedBots = new Map<string, BlockedBot>();
  private events: SecurityEvent[] = [];
  private stats = new TtlMap<Record<string, number>>(5_000);
  private tops = new TtlMap<Map<string, number>>(1_000);
  private cf = new TtlMap<{ ruleId: string; expiresAt: number }>(10_000);
  private flags = new TtlMap<boolean>(50_000);
  private audit: boolean | null = null;

  constructor(private readonly clock: () => number = Date.now) {}

  async apply(i: ApplyInput, p: ScoringParams): Promise<ApplyResult> {
    const now = i.now;
    const decayPerMs = p.decayPerMinute / 60_000;
    const cur = this.rep.get(i.ipKey, now);
    const dec = cur ? Math.max(0, now - cur.t) * decayPerMs : 0;
    let s = cur ? Math.max(0, cur.s - dec) : 0;
    let g = cur ? Math.max(0, cur.g - dec) : 0;
    let wh = cur?.wh ?? 0;
    let ws = cur?.ws ?? 0;
    const fcur = this.fp.get(i.fpKey, now);
    let fs = fcur ? Math.max(0, fcur.s - Math.max(0, now - fcur.t) * decayPerMs) : 0;
    let bonus = 0;

    if (i.ipDelta > 0 || i.isHit) {
      if (i.isHit) {
        if (now - ws > p.burstWindowMs) {
          ws = now;
          wh = 0;
        }
        wh++;
        if (wh === p.burstThreshold) bonus = p.burstBonus;
      }
      s += i.ipDelta + bonus;
      g += i.strongDelta + bonus;
      this.rep.set(
        i.ipKey,
        {
          s,
          g,
          t: now,
          wh,
          ws,
          f: cur?.f ?? now,
          l: now,
          h: (cur?.h ?? 0) + (i.isHit ? 1 : 0),
          cc: i.country || cur?.cc,
        },
        i.ipTtlSec * 1000,
        now,
      );
    }
    if (i.fpDelta > 0) {
      fs += i.fpDelta;
      this.fp.set(i.fpKey, { s: fs, t: now }, i.fpTtlSec * 1000, now);
      const set = this.fpsByIp.get(i.ipKey, now) ?? new Set<string>();
      if (set.size < 500) set.add(i.fpKey);
      this.fpsByIp.set(i.ipKey, set, i.fpTtlSec * 1000, now);
    }
    if (i.reason || bonus > 0) {
      const r = [i.reason, bonus > 0 ? `rapid_scanning+${bonus}` : ''].filter(Boolean).join(',');
      const list = this.reasons.get(i.ipKey, now) ?? [];
      list.unshift({ at: now, reason: r });
      this.reasons.set(i.ipKey, list.slice(0, p.reasonsMax), Math.max(i.ipTtlSec * 1000, DAY), now);
    }
    const pfx = i.audit ? 'audit:' : '';
    return {
      ipBanTtlMs: this.bans.ttlMs(`${pfx}ip|${i.ipKey}`, now),
      fpBanTtlMs: this.bans.ttlMs(`${pfx}fp|${i.fpKey}`, now),
      ipScore: Math.floor(s * 100) / 100,
      strongScore: Math.floor(g * 100) / 100,
      fpScore: Math.floor(fs * 100) / 100,
      burstBonus: bonus,
      decay: Math.floor(Math.min(cur?.s ?? 0, dec) * 100) / 100,
      windowHits: wh,
    };
  }

  async throttle(key: string, windowSec: number): Promise<number> {
    const c = (this.counters.get(key) ?? 0) + 1;
    const ttl = this.counters.ttlMs(key);
    this.counters.set(key, c, ttl > 0 ? ttl : windowSec * 1000);
    return c;
  }

  async setBan(r: BanRecord): Promise<void> {
    this.bans.set(`${r.audit ? 'audit:' : ''}${banIndexMember(r.scope, r.key)}`, r, Math.max(1, r.expiresAt - this.clock()));
  }
  async getBan(scope: BanScope, key: string, audit: boolean): Promise<BanRecord | null> {
    return this.bans.get(`${audit ? 'audit:' : ''}${banIndexMember(scope, key)}`) ?? null;
  }
  async deleteBan(scope: BanScope, key: string): Promise<boolean> {
    const a = this.bans.delete(banIndexMember(scope, key));
    const b = this.bans.delete(`audit:${banIndexMember(scope, key)}`);
    return a || b;
  }
  async listBans(audit: boolean, offset: number, limit: number): Promise<BanRecord[]> {
    return this.bans
      .entries()
      .filter(([k]) => k.startsWith('audit:') === audit)
      .map(([, v]) => v)
      .sort((a, b) => b.expiresAt - a.expiresAt)
      .slice(offset, offset + limit);
  }
  async countBans(audit: boolean): Promise<number> {
    return this.bans.entries().filter(([k]) => k.startsWith('audit:') === audit).length;
  }
  async incrRecidivism(ipKey: string, ttlSec: number): Promise<number> {
    const n = (this.recid.get(ipKey) ?? 0) + 1;
    this.recid.set(ipKey, n, ttlSec * 1000);
    return n;
  }
  async getRecidivism(ipKey: string): Promise<number> {
    return this.recid.get(ipKey) ?? 0;
  }
  async getIpState(ipKey: string): Promise<IpState | null> {
    const h = this.rep.get(ipKey);
    const reasons = this.reasons.get(ipKey) ?? [];
    const recidivism = this.recid.get(ipKey) ?? 0;
    if (!h && reasons.length === 0 && recidivism === 0) return null;
    return {
      score: h?.s ?? 0,
      updatedAt: h?.t,
      strong: h?.g ?? 0,
      firstSeen: h?.f,
      lastSeen: h?.l,
      hits: h?.h ?? 0,
      country: h?.cc,
      reasons,
      recidivism,
    };
  }
  async resetIp(ipKey: string, fpKeys: string[]): Promise<void> {
    this.rep.delete(ipKey);
    this.reasons.delete(ipKey);
    this.recid.delete(ipKey);
    for (const f of [...fpKeys, ...(this.fpsByIp.get(ipKey) ?? [])]) this.fp.delete(f);
    this.fpsByIp.delete(ipKey);
  }

  async getDns(ip: string): Promise<string | null> {
    return this.dns.get(ip) ?? null;
  }
  async setDns(ip: string, value: string, ttlSec: number): Promise<void> {
    this.dns.set(ip, value, ttlSec * 1000);
  }
  async getAuditOverride(): Promise<boolean | null> {
    return this.audit;
  }
  async setAuditOverride(audit: boolean): Promise<void> {
    this.audit = audit;
  }
  async listAllow(): Promise<AllowEntry[]> {
    const now = this.clock();
    return [...this.allow.values()].filter((e) => !e.expiresAt || e.expiresAt > now);
  }
  async setAllow(entry: AllowEntry): Promise<void> {
    this.allow.set(entry.value, entry);
  }
  async deleteAllow(value: string): Promise<boolean> {
    return this.allow.delete(value);
  }
  async listBlockedBots(): Promise<BlockedBot[]> {
    const now = this.clock();
    return [...this.blockedBots.values()].filter((e) => !e.expiresAt || e.expiresAt > now);
  }
  async setBlockedBot(entry: BlockedBot): Promise<void> {
    this.blockedBots.set(entry.pattern, entry);
  }
  async deleteBlockedBot(pattern: string): Promise<boolean> {
    return this.blockedBots.delete(pattern);
  }
  async pushEvents(events: SecurityEvent[], maxLen: number): Promise<void> {
    this.events.unshift(...events.slice().reverse());
    if (this.events.length > maxLen) this.events.length = maxLen;
  }
  async listEvents(limit: number): Promise<SecurityEvent[]> {
    return this.events.slice(0, limit);
  }
  async flushStats(minute: number, fields: Record<string, number>, _ips: string[], top: TopIncrements): Promise<void> {
    const cur = this.stats.get(String(minute)) ?? {};
    for (const [k, v] of Object.entries(fields)) cur[k] = (cur[k] ?? 0) + v;
    this.stats.set(String(minute), cur, 2 * DAY);
    for (const kind of ['paths', 'ips', 'rules'] as const) {
      const key = `${kind}:${top.hour}`;
      const m = this.tops.get(key) ?? new Map<string, number>();
      for (const [k, v] of top[kind]) m.set(k, (m.get(k) ?? 0) + v);
      this.tops.set(key, m, 2 * DAY);
    }
  }
  async readStats(minutes: number[]): Promise<StatsBucket[]> {
    return minutes.map((minute) => ({ minute, fields: this.stats.get(String(minute)) ?? {} }));
  }
  async readActiveIps(): Promise<number> {
    return this.rep.size;
  }
  async readTop(kind: 'paths' | 'ips' | 'rules', hours: number[], limit: number): Promise<{ member: string; score: number }[]> {
    const agg = new Map<string, number>();
    for (const h of hours) for (const [k, v] of this.tops.get(`${kind}:${h}`) ?? []) agg.set(k, (agg.get(k) ?? 0) + v);
    return [...agg.entries()]
      .map(([member, score]) => ({ member, score }))
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }
  async getCfRule(ipKey: string): Promise<{ ruleId: string; expiresAt: number } | null> {
    return this.cf.get(ipKey) ?? null;
  }
  async setCfRule(ipKey: string, ruleId: string, expiresAt: number): Promise<void> {
    this.cf.set(ipKey, { ruleId, expiresAt }, Math.max(1, expiresAt - this.clock()) + DAY);
  }
  async deleteCfRule(ipKey: string): Promise<void> {
    this.cf.delete(ipKey);
  }
  async dueCfRules(now: number, limit: number): Promise<string[]> {
    return this.cf
      .entries()
      .filter(([, v]) => v.expiresAt <= now)
      .slice(0, limit)
      .map(([k]) => k);
  }
  async countCfRules(): Promise<number> {
    return this.cf.entries().length;
  }
  async once(key: string, ttlSec: number): Promise<boolean> {
    if (this.flags.get(key)) return false;
    this.flags.set(key, true, ttlSec * 1000);
    return true;
  }
}
