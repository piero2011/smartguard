import { BanRecord, BanScope, SecurityEvent } from '../common/types';
import { RedisService } from '../redis/redis.service';
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

const DAY_SEC = 86_400;
const TOP_KEEP = 500;

/**
 * Esquema de claves (todas con prefijo REDIS_PREFIX, por defecto "smartguard:") y TTL obligatorio:
 *
 *  ip:{ipKey}              hash reputación                     TTL IP_TTL_SEC (1 h, renovado con actividad maliciosa)
 *  fp:{hash}               hash huella IP+UA                    TTL FP_TTL_SEC (30 min)
 *  fps:{ipKey}             SET de huellas de la IP (≤500)        TTL FP_TTL_SEC (reset al desbloquear)
 *  reasons:{ipKey}         lista de motivos (acotada)            TTL ≥ 24 h
 *  ban:{ipKey} / ban:fp:{} ban activo (JSON)                     TTL = duración del ban
 *  auditban:...            "ban que se habría aplicado" (AUDIT)  TTL = duración
 *  bans / auditbans        índice ZSET (score = expiresAt)       limpiado en cada inserción
 *  recid:{ipKey}           contador de reincidencia              TTL RECIDIVISM_TTL_SEC (14 d)
 *  rl:{key}:{ventana}      throttle RATE_LIMIT                    TTL = ventana
 *  dns:{ip}                resultado FCrDNS                       TTL 6–24 h
 *  allow                   hash de allowlist dinámica             sin TTL (pocas entradas, gestionado por admin)
 *  events                  STREAM de eventos                      MAXLEN ~ EVENTS_STREAM_MAXLEN
 *  stats:{minuto}          hash de contadores por minuto          TTL 48 h
 *  hll:ips:{minuto}        HyperLogLog IPs activas (12 KB máx)    TTL 48 h
 *  top:{paths|ips|rules}:{hora}  ZSET recortado a 500             TTL 48 h
 *  cf:{ipKey} / cf:rules   reglas Cloudflare creadas + índice     TTL = ban + 1 d
 *  once:{...}              deduplicación (alertas, CF)            TTL corto
 *  config:audit            override de AUDIT_MODE en caliente     sin TTL
 *
 * Nunca se usa KEYS: los listados usan índices ZSET (y SCAN solo en scripts de desinstalación).
 */
export class RedisReputationStore implements ReputationStore {
  readonly kind = 'redis' as const;

  constructor(private readonly redis: RedisService) {}

  private k(s: string): string {
    return this.redis.key(s);
  }

  private banKey(scope: BanScope, key: string, audit: boolean): string {
    return this.k(`${audit ? 'auditban' : 'ban'}:${scope === 'fp' ? 'fp:' : ''}${key}`);
  }

  async apply(i: ApplyInput, p: ScoringParams): Promise<ApplyResult> {
    const r = await this.redis.run((c) =>
      c.sgDecide(
        this.k(`ip:${i.ipKey}`),
        this.k(`fp:${i.fpKey}`),
        this.banKey('ip', i.ipKey, i.audit),
        this.banKey('fp', i.fpKey, i.audit),
        this.k(`reasons:${i.ipKey}`),
        this.k(`fps:${i.ipKey}`),
        i.now,
        i.ipDelta,
        i.fpDelta,
        i.strongDelta,
        p.decayPerMinute,
        i.ipTtlSec,
        i.fpTtlSec,
        p.burstWindowMs,
        p.burstThreshold,
        p.burstBonus,
        i.reason,
        p.reasonsMax,
        i.isHit ? 1 : 0,
        i.country,
        i.fpKey,
      ),
    );
    return {
      ipBanTtlMs: Number(r[0]),
      fpBanTtlMs: Number(r[1]),
      ipScore: Number(r[2]) / 100,
      strongScore: Number(r[3]) / 100,
      fpScore: Number(r[4]) / 100,
      burstBonus: Number(r[5]),
      decay: Number(r[6]) / 100,
      windowHits: Number(r[7]),
    };
  }

  async throttle(key: string, windowSec: number): Promise<number> {
    const bucket = Math.floor(Date.now() / 1000 / windowSec);
    return Number(await this.redis.run((c) => c.sgThrottle(this.k(`rl:${key}:${bucket}`), windowSec + 1)));
  }

  async setBan(r: BanRecord): Promise<void> {
    const ttl = Math.max(1, Math.ceil((r.expiresAt - Date.now()) / 1000));
    const idx = this.k(r.audit ? 'auditbans' : 'bans');
    await this.redis.run((c) =>
      c
        .multi()
        .set(this.banKey(r.scope, r.key, r.audit), JSON.stringify(r), 'EX', ttl)
        .zadd(idx, r.expiresAt, banIndexMember(r.scope, r.key))
        .zremrangebyscore(idx, '-inf', Date.now())
        .expire(idx, 30 * DAY_SEC)
        .exec(),
    );
  }

  async getBan(scope: BanScope, key: string, audit: boolean): Promise<BanRecord | null> {
    const v = await this.redis.run((c) => c.get(this.banKey(scope, key, audit)));
    return v ? (JSON.parse(v) as BanRecord) : null;
  }

  async deleteBan(scope: BanScope, key: string): Promise<boolean> {
    const m = banIndexMember(scope, key);
    const res = await this.redis.run((c) =>
      c
        .multi()
        .del(this.banKey(scope, key, false), this.banKey(scope, key, true))
        .zrem(this.k('bans'), m)
        .zrem(this.k('auditbans'), m)
        .exec(),
    );
    return Number(res?.[0]?.[1] ?? 0) > 0;
  }

  async listBans(audit: boolean, offset: number, limit: number): Promise<BanRecord[]> {
    const idx = this.k(audit ? 'auditbans' : 'bans');
    const members = await this.redis.run((c) => c.zrevrangebyscore(idx, '+inf', Date.now(), 'LIMIT', offset, limit));
    if (members.length === 0) return [];
    const keys = members.map((m) => {
      const [scope, key] = m.split('|') as [BanScope, string];
      return this.banKey(scope, key, audit);
    });
    const vals = await this.redis.run((c) => c.mget(...keys));
    return vals.filter((v): v is string => !!v).map((v) => JSON.parse(v) as BanRecord);
  }

  async countBans(audit: boolean): Promise<number> {
    return this.redis.run((c) => c.zcount(this.k(audit ? 'auditbans' : 'bans'), Date.now(), '+inf'));
  }

  async incrRecidivism(ipKey: string, ttlSec: number): Promise<number> {
    const res = await this.redis.run((c) => c.multi().incr(this.k(`recid:${ipKey}`)).expire(this.k(`recid:${ipKey}`), ttlSec).exec());
    return Number(res?.[0]?.[1] ?? 1);
  }

  async getRecidivism(ipKey: string): Promise<number> {
    return Number((await this.redis.run((c) => c.get(this.k(`recid:${ipKey}`)))) ?? 0);
  }

  async getIpState(ipKey: string): Promise<IpState | null> {
    const res = await this.redis.run((c) =>
      c.multi().hgetall(this.k(`ip:${ipKey}`)).lrange(this.k(`reasons:${ipKey}`), 0, -1).get(this.k(`recid:${ipKey}`)).exec(),
    );
    const h = (res?.[0]?.[1] ?? {}) as Record<string, string>;
    const reasonsRaw = (res?.[1]?.[1] ?? []) as string[];
    const recid = Number(res?.[2]?.[1] ?? 0);
    if (Object.keys(h).length === 0 && reasonsRaw.length === 0 && recid === 0) return null;
    return {
      score: Number(h.s ?? 0),
      updatedAt: h.t ? Number(h.t) : undefined,
      strong: Number(h.g ?? 0),
      firstSeen: h.f ? Number(h.f) : undefined,
      lastSeen: h.l ? Number(h.l) : undefined,
      hits: Number(h.h ?? 0),
      country: h.cc,
      reasons: reasonsRaw.map((r) => {
        const bar = r.indexOf('|');
        return { at: Number(r.slice(0, bar)), reason: r.slice(bar + 1) };
      }),
      recidivism: recid,
    };
  }

  async resetIp(ipKey: string, extraFpKeys: string[]): Promise<void> {
    const seen = await this.redis.run((c) => c.smembers(this.k(`fps:${ipKey}`)));
    const fpKeys = [...new Set([...seen, ...extraFpKeys])];
    const keys = [this.k(`fps:${ipKey}`), this.k(`ip:${ipKey}`), this.k(`reasons:${ipKey}`), this.k(`recid:${ipKey}`), ...fpKeys.map((f) => this.k(`fp:${f}`))];
    await this.redis.run((c) => c.unlink(...keys));
  }

  async getDns(ip: string): Promise<string | null> {
    return this.redis.run((c) => c.get(this.k(`dns:${ip}`)));
  }

  async setDns(ip: string, value: string, ttlSec: number): Promise<void> {
    await this.redis.run((c) => c.set(this.k(`dns:${ip}`), value, 'EX', ttlSec));
  }

  async getAuditOverride(): Promise<boolean | null> {
    const v = await this.redis.run((c) => c.get(this.k('config:audit')));
    return v === null ? null : v === '1';
  }

  async setAuditOverride(audit: boolean): Promise<void> {
    await this.redis.run((c) => c.set(this.k('config:audit'), audit ? '1' : '0'));
  }

  async listAllow(): Promise<AllowEntry[]> {
    const h = await this.redis.run((c) => c.hgetall(this.k('allow')));
    const now = Date.now();
    const out: AllowEntry[] = [];
    for (const v of Object.values(h)) {
      try {
        const raw = JSON.parse(v) as AllowEntry & { cidr?: string };
        // compatibilidad con entradas antiguas { cidr }
        const e: AllowEntry = { ...raw, value: raw.value ?? raw.cidr ?? '', kind: raw.kind ?? 'cidr', target: raw.target ?? 'client' };
        if (!e.expiresAt || e.expiresAt > now) out.push(e);
      } catch {
        /* entrada corrupta: ignorar */
      }
    }
    return out;
  }

  async setAllow(entry: AllowEntry): Promise<void> {
    await this.redis.run((c) => c.hset(this.k('allow'), entry.value, JSON.stringify(entry)));
  }

  async deleteAllow(value: string): Promise<boolean> {
    return (await this.redis.run((c) => c.hdel(this.k('allow'), value))) > 0;
  }

  async listBlockedBots(): Promise<BlockedBot[]> {
    const h = await this.redis.run((c) => c.hgetall(this.k('blockbots')));
    const now = Date.now();
    const out: BlockedBot[] = [];
    for (const v of Object.values(h)) {
      try {
        const e = JSON.parse(v) as BlockedBot;
        if (typeof e.pattern === 'string' && (!e.expiresAt || e.expiresAt > now)) out.push(e);
      } catch {
        /* entrada corrupta: ignorar */
      }
    }
    return out;
  }

  async setBlockedBot(entry: BlockedBot): Promise<void> {
    await this.redis.run((c) => c.hset(this.k('blockbots'), entry.pattern, JSON.stringify(entry)));
  }

  async deleteBlockedBot(pattern: string): Promise<boolean> {
    return (await this.redis.run((c) => c.hdel(this.k('blockbots'), pattern))) > 0;
  }

  async pushEvents(events: SecurityEvent[], maxLen: number): Promise<void> {
    if (events.length === 0) return;
    await this.redis.run((c) => {
      const p = c.pipeline();
      for (const e of events) p.xadd(this.k('events'), 'MAXLEN', '~', maxLen, '*', 'e', JSON.stringify(e));
      return p.exec();
    });
  }

  async listEvents(limit: number): Promise<SecurityEvent[]> {
    const rows = await this.redis.run((c) => c.xrevrange(this.k('events'), '+', '-', 'COUNT', limit));
    const out: SecurityEvent[] = [];
    for (const [, fields] of rows) {
      const i = fields.indexOf('e');
      if (i >= 0 && fields[i + 1]) {
        try {
          out.push(JSON.parse(fields[i + 1]!) as SecurityEvent);
        } catch {
          /* ignorar */
        }
      }
    }
    return out;
  }

  async flushStats(minute: number, fields: Record<string, number>, ips: string[], top: TopIncrements): Promise<void> {
    await this.redis.run((c) => {
      const p = c.pipeline();
      const sk = this.k(`stats:${minute}`);
      for (const [f, v] of Object.entries(fields)) if (v) p.hincrby(sk, f, v);
      p.expire(sk, 2 * DAY_SEC);
      if (ips.length) {
        const hk = this.k(`hll:ips:${minute}`);
        for (let i = 0; i < ips.length; i += 500) p.pfadd(hk, ...ips.slice(i, i + 500));
        p.expire(hk, 2 * DAY_SEC);
      }
      for (const kind of ['paths', 'ips', 'rules'] as const) {
        const m = top[kind];
        if (m.size === 0) continue;
        const zk = this.k(`top:${kind}:${top.hour}`);
        for (const [member, inc] of m) p.zincrby(zk, inc, member.slice(0, 200));
        p.zremrangebyrank(zk, 0, -(TOP_KEEP + 1));
        p.expire(zk, 2 * DAY_SEC);
      }
      return p.exec();
    });
  }

  async readStats(minutes: number[]): Promise<StatsBucket[]> {
    const res = await this.redis.run((c) => {
      const p = c.pipeline();
      for (const m of minutes) p.hgetall(this.k(`stats:${m}`));
      return p.exec();
    });
    return minutes.map((minute, i) => {
      const h = (res?.[i]?.[1] ?? {}) as Record<string, string>;
      const fields: Record<string, number> = {};
      for (const [k, v] of Object.entries(h)) fields[k] = Number(v);
      return { minute, fields };
    });
  }

  async readActiveIps(minutes: number[]): Promise<number> {
    if (minutes.length === 0) return 0;
    return this.redis.run((c) => c.pfcount(...minutes.map((m) => this.k(`hll:ips:${m}`))));
  }

  async readTop(kind: 'paths' | 'ips' | 'rules', hours: number[], limit: number): Promise<{ member: string; score: number }[]> {
    const res = await this.redis.run((c) => {
      const p = c.pipeline();
      for (const h of hours) p.zrevrange(this.k(`top:${kind}:${h}`), 0, limit * 2, 'WITHSCORES');
      return p.exec();
    });
    const agg = new Map<string, number>();
    for (const r of res ?? []) {
      const arr = (r?.[1] ?? []) as string[];
      for (let i = 0; i + 1 < arr.length; i += 2) agg.set(arr[i]!, (agg.get(arr[i]!) ?? 0) + Number(arr[i + 1]));
    }
    return [...agg.entries()]
      .map(([member, score]) => ({ member, score }))
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }

  async getCfRule(ipKey: string): Promise<{ ruleId: string; expiresAt: number } | null> {
    const v = await this.redis.run((c) => c.get(this.k(`cf:${ipKey}`)));
    return v ? (JSON.parse(v) as { ruleId: string; expiresAt: number }) : null;
  }

  async setCfRule(ipKey: string, ruleId: string, expiresAt: number): Promise<void> {
    const ttl = Math.max(60, Math.ceil((expiresAt - Date.now()) / 1000) + DAY_SEC);
    await this.redis.run((c) =>
      c
        .multi()
        .set(this.k(`cf:${ipKey}`), JSON.stringify({ ruleId, expiresAt }), 'EX', ttl)
        .zadd(this.k('cf:rules'), expiresAt, ipKey)
        .exec(),
    );
  }

  async deleteCfRule(ipKey: string): Promise<void> {
    await this.redis.run((c) => c.multi().del(this.k(`cf:${ipKey}`)).zrem(this.k('cf:rules'), ipKey).exec());
  }

  async dueCfRules(now: number, limit: number): Promise<string[]> {
    return this.redis.run((c) => c.zrangebyscore(this.k('cf:rules'), '-inf', now, 'LIMIT', 0, limit));
  }

  async countCfRules(): Promise<number> {
    return this.redis.run((c) => c.zcard(this.k('cf:rules')));
  }

  async once(key: string, ttlSec: number): Promise<boolean> {
    return (await this.redis.run((c) => c.set(this.k(`once:${key}`), '1', 'EX', ttlSec, 'NX'))) === 'OK';
  }
}
