import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SystemInfoService } from '../../src/admin/system-info.service';
import { detectDeployment } from '../../src/common/deployment';
import { MemoryReputationStore } from '../../src/reputation/memory.store';

describe('Tipo de despliegue', () => {
  it('la variable manda; sin ella decide /.dockerenv', () => {
    expect(detectDeployment({ SMARTGUARD_DEPLOYMENT: 'docker' }, () => false)).toBe('docker');
    expect(detectDeployment({ SMARTGUARD_DEPLOYMENT: 'system' }, () => true)).toBe('system');
    expect(detectDeployment({}, (p) => p === '/.dockerenv')).toBe('docker');
    expect(detectDeployment({}, () => false)).toBe('system');
  });
});

describe('Recursos que ocupa SmartGuard', () => {
  const store = new MemoryReputationStore();
  const config = { env: { configDir: '/no-existe/etc', analyzerLogPath: '/no-existe/log/access.json', eventsStreamMaxLen: 20000 } };
  const reputation = { degraded: false, call: <T>(fn: (s: MemoryReputationStore) => Promise<T>) => fn(store) };
  const svc = new SystemInfoService(config as never, reputation as never);

  it('mide una carpeta con subcarpetas y devuelve null si no existe', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sg-size-'));
    await fs.mkdir(path.join(dir, 'sub'));
    await fs.writeFile(path.join(dir, 'a.bin'), Buffer.alloc(8192));
    await fs.writeFile(path.join(dir, 'sub', 'b.bin'), Buffer.alloc(4096));
    expect(await svc.dirSize(dir)).toBeGreaterThanOrEqual(12288);
    expect(await svc.dirSize(path.join(dir, 'nope'))).toBeNull();
    await fs.rm(dir, { recursive: true });
  });

  it('informa de versión, memoria, disco por carpeta y almacén', async () => {
    const info = (await svc.info()) as { version: string; memory: { rss: number }; disk: { id: string; bytes: number | null }[]; diskTotal: number; redis: { events: number; eventsMax: number } };
    expect(info.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(['docker', 'system']).toContain((info as unknown as { deployment: string }).deployment);
    expect(info.memory.rss).toBeGreaterThan(0);
    expect(info.disk.map((d) => d.id)).toEqual(['app', 'prev', 'src', 'config', 'nginx', 'data', 'logs', 'backups']);
    expect(info.disk.find((d) => d.id === 'config')!.bytes).toBeNull();
    expect(info.diskTotal).toBeGreaterThan(0);
    expect(info.redis).toMatchObject({ events: 0, eventsMax: 20000 });
  }, 120_000);
});
