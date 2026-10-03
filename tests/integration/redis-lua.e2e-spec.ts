/**
 * Verifica que el script Lua (Redis) y el almacén en memoria tienen la MISMA semántica.
 * Requiere un Redis de pruebas. Se omite salvo que exista SMARTGUARD_TEST_REDIS:
 *   SMARTGUARD_TEST_REDIS=1 REDIS_HOST=127.0.0.1 REDIS_PORT=6379 REDIS_DB=15 npx jest tests/integration/redis-lua
 * Usa el prefijo "smartguard-test:" y lo limpia al terminar (SCAN, nunca KEYS).
 */
import { ConfigService } from '../../src/config/config.service';
import { RedisService } from '../../src/redis/redis.service';
import { RedisReputationStore } from '../../src/reputation/redis.store';
import { MemoryReputationStore } from '../../src/reputation/memory.store';
import { ApplyInput, ScoringParams } from '../../src/reputation/reputation.store';
import { testEnv } from '../helpers';

const enabled = !!process.env.SMARTGUARD_TEST_REDIS;
const d = enabled ? describe : describe.skip;

d('Lua de decisión en Redis real', () => {
  let redis: RedisService;
  let store: RedisReputationStore;
  const params: ScoringParams = { decayPerMinute: 2, burstWindowMs: 60_000, burstThreshold: 4, burstBonus: 20, reasonsMax: 50 };

  beforeAll(async () => {
    const env = testEnv({
      REDIS_ENABLED: 'true',
      REDIS_HOST: process.env.REDIS_HOST ?? '127.0.0.1',
      REDIS_PORT: process.env.REDIS_PORT ?? '6379',
      REDIS_DB: process.env.REDIS_DB ?? '15',
      REDIS_PASSWORD: process.env.REDIS_PASSWORD ?? '',
      REDIS_PREFIX: 'smartguard-test:',
      REDIS_COMMAND_TIMEOUT_MS: '500',
    });
    redis = new RedisService(new ConfigService(env));
    for (let i = 0; i < 50 && redis.client!.status !== 'ready'; i++) await new Promise((r) => setTimeout(r, 100));
    store = new RedisReputationStore(redis);
  });

  afterAll(async () => {
    let cursor = '0';
    do {
      const [next, keys] = await redis.client!.scan(cursor, 'MATCH', 'smartguard-test:*', 'COUNT', 500);
      if (keys.length) await redis.client!.unlink(...keys);
      cursor = next;
    } while (cursor !== '0');
    await redis.onModuleDestroy();
  });

  const input = (o: Partial<ApplyInput>): ApplyInput => ({
    ipKey: '192.0.2.1',
    fpKey: 'fp1',
    now: Date.now(),
    ipDelta: 0,
    fpDelta: 0,
    strongDelta: 0,
    isHit: false,
    reason: '',
    ipTtlSec: 600,
    fpTtlSec: 600,
    country: '',
    audit: false,
    ...o,
  });

  it('tráfico sin señales no crea claves', async () => {
    const r = await store.apply(input({ ipKey: '192.0.2.9', fpKey: 'fp9' }), params);
    expect(r.ipScore).toBe(0);
    expect(await redis.client!.exists('smartguard-test:ip:192.0.2.9')).toBe(0);
  });

  it('misma semántica que la implementación en memoria (deltas, bonus, decay)', async () => {
    const mem = new MemoryReputationStore();
    const t0 = Date.now() - 20 * 60_000;
    const seq: Partial<ApplyInput>[] = [
      { now: t0, ipDelta: 25, fpDelta: 25, strongDelta: 25, isHit: true, reason: 'env-scan+25' },
      { now: t0 + 1000, ipDelta: 25, fpDelta: 25, strongDelta: 25, isHit: true, reason: 'git-scan+25' },
      { now: t0 + 2000, ipDelta: 15, fpDelta: 15, strongDelta: 15, isHit: true, reason: 'phpinfo+15' },
      { now: t0 + 3000, ipDelta: 10, fpDelta: 10, strongDelta: 0, isHit: true, reason: 'x+10' },
      { now: t0 + 20 * 60_000 },
    ];
    for (const s of seq) {
      const a = await store.apply(input({ ipKey: '192.0.2.2', fpKey: 'fp2', ...s }), params);
      const b = await mem.apply(input({ ipKey: '192.0.2.2', fpKey: 'fp2', ...s }), params);
      expect(a.ipScore).toBeCloseTo(b.ipScore, 1);
      expect(a.strongScore).toBeCloseTo(b.strongScore, 1);
      expect(a.fpScore).toBeCloseTo(b.fpScore, 1);
      expect(a.burstBonus).toBe(b.burstBonus);
    }
    const ttl = await redis.client!.ttl('smartguard-test:ip:192.0.2.2');
    expect(ttl).toBeGreaterThan(0);
  });

  it('ban → PTTL visible en la siguiente decisión', async () => {
    await store.setBan({
      ip: '192.0.2.3', key: '192.0.2.3', scope: 'ip', reason: 't', score: 90, reasons: [], createdAt: Date.now(),
      expiresAt: Date.now() + 60_000, durationSec: 60, source: 'MANUAL', banCount: 1, audit: false, firewall: false,
    });
    const r = await store.apply(input({ ipKey: '192.0.2.3' }), params);
    expect(r.ipBanTtlMs).toBeGreaterThan(50_000);
    expect((await store.listBans(false, 0, 10)).map((b) => b.key)).toContain('192.0.2.3');
  });
});
