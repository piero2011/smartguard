import { SecurityEvent } from '../../src/common/types';
import { MemoryReputationStore } from '../../src/reputation/memory.store';
import { RedisReputationStore, previousStreamId } from '../../src/reputation/redis.store';
import { eventMatches } from '../../src/reputation/reputation.store';

const ev = (timestamp: number, ip: string, ipKey = ip): SecurityEvent => ({
  timestamp,
  ip,
  ipKey,
  host: 'example.com',
  method: 'GET',
  uri: '/.env',
  userAgent: 'curl',
  category: 'SCANNER',
  severity: 'high',
  scoreDelta: 25,
  reason: 'env-scan',
  source: 'decision',
});

describe('Búsqueda de eventos por fechas e IP', () => {
  it('filtra por rango (extremos incluidos) y por IP o clave /64', () => {
    const e = ev(1000, '2001:db8::1', '2001:db8::/64');
    expect(eventMatches(e, { from: 1000, to: 1000 })).toBe(true);
    expect(eventMatches(e, { from: 1001 })).toBe(false);
    expect(eventMatches(e, { to: 999 })).toBe(false);
    expect(eventMatches(e, { ip: '2001:db8::1' })).toBe(true);
    expect(eventMatches(e, { ip: '2001:db8::/64' })).toBe(true);
    expect(eventMatches(e, { ip: '2001:db8::2' })).toBe(false);
  });

  it('el almacén busca en todo lo guardado, no solo en los últimos', async () => {
    const store = new MemoryReputationStore();
    await store.pushEvents([ev(100, '198.51.100.7'), ...Array.from({ length: 50 }, (_, i) => ev(200 + i, '203.0.113.9'))], 1000);
    expect(await store.listEvents(10)).toHaveLength(10);
    expect((await store.listEvents(10, { ip: '198.51.100.7' })).map((e) => e.timestamp)).toEqual([100]);
    expect((await store.listEvents(1000, { from: 240, to: 244 })).map((e) => e.timestamp)).toEqual([244, 243, 242, 241, 240]);
  });

  it('filtra por tipo de evento y por texto libre', () => {
    const blocked: SecurityEvent = { ...ev(1, '198.51.100.7'), action: 'BLOCK', status: 403, userAgent: 'DotBot/1.2' };
    expect(eventMatches(blocked, { kind: 'blocked' })).toBe(true);
    expect(eventMatches(blocked, { kind: 'limited' })).toBe(false);
    expect(eventMatches(blocked, { kind: 'st403', text: 'dotbot' })).toBe(true);
    expect(eventMatches(blocked, { text: '/.env' })).toBe(true);
    expect(eventMatches(blocked, { text: 'wp-login' })).toBe(false);
  });

  it('pagina con cursor sin repetir ni saltarse eventos', async () => {
    const store = new MemoryReputationStore();
    // del más antiguo al más reciente; las IPs alternan para paginar también con filtro
    await store.pushEvents(Array.from({ length: 25 }, (_, i) => ev(i, i % 2 ? '203.0.113.9' : '198.51.100.7')), 1000);
    const seen: number[] = [];
    let cursor: string | undefined;
    for (let pages = 0; pages < 10; pages++) {
      const page = await store.pageEvents(10, {}, cursor);
      seen.push(...page.items.map((e) => e.timestamp));
      if (!page.next) break;
      cursor = page.next;
    }
    expect(seen).toEqual(Array.from({ length: 25 }, (_, i) => 24 - i));

    const first = await store.pageEvents(5, { text: '203.0.113.9' });
    expect(first.items.map((e) => e.timestamp)).toEqual([23, 21, 19, 17, 15]);
    const second = await store.pageEvents(5, { text: '203.0.113.9' }, first.next!);
    expect(second.items.map((e) => e.timestamp)).toEqual([13, 11, 9, 7, 5]);
  });

  it('Redis: pagina el stream por cursor, con y sin filtros, y respeta el rango de fechas', async () => {
    // Stream simulado: XREVRANGE con los mismos límites inclusivos que Redis ("ms" = ms-0 al inicio, ms-máx al final).
    const rows: [string, string[]][] = [];
    const bound = (v: string, seqDefault: bigint): [bigint, bigint] => {
      const [ms, seq] = v.split('-');
      return [BigInt(ms!), seq === undefined ? seqDefault : BigInt(seq)];
    };
    const le = (a: [bigint, bigint], b: [bigint, bigint]) => a[0] < b[0] || (a[0] === b[0] && a[1] <= b[1]);
    const client = {
      xrevrange: async (_k: string, end: string, start: string, _c: string, count: number) =>
        rows
          .filter(([id]) => (end === '+' || le(bound(id, 0n), bound(end, 18446744073709551615n))) && (start === '-' || le(bound(start, 0n), bound(id, 0n))))
          .slice(0, count),
    };
    const redis = { key: (s: string) => s, run: <T>(fn: (c: typeof client) => Promise<T>) => fn(client) };
    const store = new RedisReputationStore(redis as never);
    // 1300 eventos (más de dos lotes de lectura), del más reciente al más antiguo; dos por milisegundo
    for (let i = 1299; i >= 0; i--) {
      const ms = 1_700_000_000_000 + Math.floor(i / 2);
      rows.push([`${ms}-${i % 2}`, ['e', JSON.stringify(ev(ms, i % 100 === 0 ? '198.51.100.7' : '203.0.113.9'))]]);
    }
    const walk = async (query: Parameters<typeof store.pageEvents>[1], limit: number) => {
      const out: SecurityEvent[] = [];
      let cursor: string | undefined;
      for (let pages = 0; pages < 200; pages++) {
        const page = await store.pageEvents(limit, query, cursor);
        out.push(...page.items);
        if (!page.next) break;
        cursor = page.next;
      }
      return out;
    };
    expect(await walk({}, 50)).toHaveLength(1300);
    expect((await store.pageEvents(50, {})).items).toHaveLength(50);
    expect(await walk({ text: '198.51.100.7' }, 5)).toHaveLength(13);
    const ranged = await walk({ from: 1_700_000_000_100, to: 1_700_000_000_149 }, 30);
    expect(ranged).toHaveLength(100);
    expect(ranged.every((e) => e.timestamp >= 1_700_000_000_100 && e.timestamp <= 1_700_000_000_149)).toBe(true);
    expect(await store.listEvents(1000, { ip: '198.51.100.7' })).toHaveLength(13);
  });

  it('ID anterior de un stream de Redis', () => {
    expect(previousStreamId('1700000000000-3')).toBe('1700000000000-2');
    expect(previousStreamId('1700000000000-0')).toBe('1699999999999-18446744073709551615');
  });
});
