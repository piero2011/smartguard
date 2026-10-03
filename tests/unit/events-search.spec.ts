import { SecurityEvent } from '../../src/common/types';
import { MemoryReputationStore } from '../../src/reputation/memory.store';
import { previousStreamId } from '../../src/reputation/redis.store';
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

  it('ID anterior de un stream de Redis', () => {
    expect(previousStreamId('1700000000000-3')).toBe('1700000000000-2');
    expect(previousStreamId('1700000000000-0')).toBe('1699999999999-18446744073709551615');
  });
});
