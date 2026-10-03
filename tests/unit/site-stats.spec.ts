import { MemoryReputationStore } from '../../src/reputation/memory.store';
import { HOST_FIELD_PREFIX } from '../../src/reputation/reputation.store';
import { StatsService, currentMinute } from '../../src/stats/stats.service';

function make(known?: string[]) {
  const store = new MemoryReputationStore();
  const reputation = { call: <T>(fn: (s: MemoryReputationStore) => Promise<T>) => fn(store) };
  const sites = known ? { list: async () => ({ readable: true, items: [{ status: 'full', names: known }] }) } : undefined;
  const stats = new StatsService({ env: { eventsStreamMaxLen: 100 } } as never, reputation as never, sites as never);
  return { store, stats };
}

describe('Estadísticas por sitio', () => {
  it('cada contador suma al total y al sitio; los "top" también se separan', async () => {
    const { store, stats } = make();
    stats.incr('requests', 1, 'Shop.Test');
    stats.incr('requests', 1, 'shop.test:443');
    stats.incr('requests', 1, 'blog.test');
    stats.incr('requests');
    stats.attack('203.0.113.9', '/.env', ['env-scan'], 25, 'shop.test');
    stats.attack('198.51.100.7', '/wp-login.php', ['login'], 5, 'blog.test');
    await stats.flush();
    const [bucket] = await store.readStats([currentMinute()]);
    expect(bucket!.fields).toMatchObject({ requests: 4, [`${HOST_FIELD_PREFIX}shop.test:requests`]: 2, [`${HOST_FIELD_PREFIX}blog.test:requests`]: 1 });
    const hour = [Math.floor((currentMinute() * 60) / 3600)];
    expect((await store.readTop('paths', hour, 10)).map((r) => r.member).sort()).toEqual(['/.env', '/wp-login.php']);
    expect(await store.readTop('paths', hour, 10, 'shop.test')).toEqual([{ member: '/.env', score: 1 }]);
    expect(await store.readTop('ips', hour, 10, 'blog.test')).toEqual([{ member: '198.51.100.7', score: 5 }]);
  });

  it('con los sitios protegidos conocidos, un Host ajeno o inválido solo cuenta en el total', async () => {
    const { store, stats } = make(['shop.test']);
    stats.onModuleInit();
    await new Promise((r) => setTimeout(r, 20));
    stats.incr('requests', 1, 'shop.test');
    stats.incr('requests', 1, 'evil.example');
    stats.incr('requests', 1, '"><script>');
    expect(stats.siteName('evil.example')).toBeNull();
    await stats.onModuleDestroy();
    const [bucket] = await store.readStats([currentMinute()]);
    expect(Object.keys(bucket!.fields).sort()).toEqual([`${HOST_FIELD_PREFIX}shop.test:requests`, 'requests']);
    expect(bucket!.fields['requests']).toBe(3);
  });

  it('sin lista de sitios, el número de hosts distintos por volcado está acotado', async () => {
    const { stats } = make();
    for (let i = 0; i < StatsService.MAX_HOSTS_BUFFER + 10; i++) stats.incr('requests', 1, `h${i}.test`);
    expect(stats.siteName('uno-mas.test')).toBeNull();
    expect(stats.siteName('h0.test')).toBe('h0.test');
    await stats.flush();
  });
});
