import 'reflect-metadata';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Test } from '@nestjs/testing';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { AppModule } from '../../src/app.module';
import { ConfigService } from '../../src/config/config.service';
import { configureApp, createAdapter } from '../../src/main';
import { SavedState, exportState, importPlan, importState, remaining } from '../../src/admin/state-cli';
import { testEnv } from '../helpers';

const TOKEN = 'test-admin-token-0123456789abcdef0123456789';

async function makeApp(): Promise<{ app: NestFastifyApplication; url: string }> {
  const config = new ConfigService(testEnv({ AUDIT_MODE: 'false' }));
  await config.loadFiles();
  const mod = await Test.createTestingModule({ imports: [AppModule.forRoot({ config })] }).compile();
  const app = mod.createNestApplication<NestFastifyApplication>(createAdapter());
  configureApp(app);
  await app.listen(0, '127.0.0.1');
  return { app, url: await app.getUrl() };
}

describe('Copia de seguridad de las listas (smartguard backup / restore)', () => {
  it('tiempo restante en el formato de la API', () => {
    const now = 1_000_000_000_000;
    expect(remaining(undefined, now)).toBeUndefined();
    expect(remaining(now - 1, now)).toBeNull();
    expect(remaining(now + 3_600_000, now)).toBe('3600');
    expect(remaining(now + 3650 * 86_400_000, now)).toBe('3650d');
  });

  it('el plan omite lo caducado y los bloqueos automáticos', () => {
    const now = 1_000_000_000_000;
    const state: SavedState = {
      version: 1,
      exportedAt: now,
      audit: false,
      allow: [{ value: 'a.test', type: 'SERVICE_ALLOWLIST', target: 'host' }, { value: '203.0.113.1/32', type: 'ADMIN_ALLOWLIST', expiresAt: now - 5 }],
      bans: [
        { ip: '198.51.100.1', scope: 'ip', source: 'MANUAL', reason: 'x', expiresAt: now + 60_000 },
        { ip: '198.51.100.2', scope: 'ip', source: 'ANALYZER', reason: 'auto', expiresAt: now + 60_000 },
        { ip: '198.51.100.3', scope: 'fp', source: 'MANUAL', reason: 'huella', expiresAt: now + 60_000 },
      ],
      bots: [{ pattern: 'dotbot' }],
      networks: [{ asn: 64500, note: 'n' }],
    };
    expect(importPlan(state, now).map((s) => s.label)).toEqual(['lista blanca a.test', 'bot dotbot', 'red AS64500', 'bloqueo 198.51.100.1']);
  });

  it('exporta de un servidor e importa en otro: lista blanca, bots y bloqueos manuales', async () => {
    const a = await makeApp();
    const b = await makeApp();
    const post = (url: string, p: string, body: unknown) =>
      fetch(`${url}${p}`, { method: 'POST', headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const get = async (url: string, p: string) => (await fetch(`${url}${p}`, { headers: { authorization: `Bearer ${TOKEN}` } })).json();
    try {
      expect((await post(a.url, '/admin/allow', { value: 'api.tienda.test', type: 'SERVICE_ALLOWLIST', target: 'host', note: 'API' })).status).toBeLessThan(300);
      expect((await post(a.url, '/admin/allow', { value: '203.0.113.50', type: 'ADMIN_ALLOWLIST', note: 'yo' })).status).toBeLessThan(300);
      expect((await post(a.url, '/admin/blocked-bots', { pattern: 'malbot', note: 'prueba' })).status).toBeLessThan(300);
      expect((await post(a.url, '/admin/ban', { ip: '198.51.100.77', duration: '3650d', reason: 'manual' })).status).toBeLessThan(300);

      const file = path.join(await fs.mkdtemp(path.join(os.tmpdir(), 'sg-state-')), 'state.json');
      process.env['SG_TOKEN'] = TOKEN;
      process.env['SG_API'] = a.url;
      await exportState(file);
      process.env['SG_API'] = b.url;
      await importState(file);
      // importar dos veces no duplica ni falla
      await importState(file);

      const allow = (await get(b.url, '/admin/allow')) as { dynamic: { value: string; target: string }[] };
      expect(allow.dynamic.map((e) => `${e.target}:${e.value}`).sort()).toEqual(['client:203.0.113.50/32', 'host:api.tienda.test']);
      expect(((await get(b.url, '/admin/blocked-bots')) as { items: { pattern: string }[] }).items.map((x) => x.pattern)).toEqual(['malbot']);
      const bans = (await get(b.url, '/admin/bans')) as { items: { ip: string; source: string }[] };
      expect(bans.items.map((x) => x.ip)).toEqual(['198.51.100.77']);
      await fs.rm(path.dirname(file), { recursive: true });
    } finally {
      delete process.env['SG_TOKEN'];
      delete process.env['SG_API'];
      await a.app.close();
      await b.app.close();
    }
  }, 60_000);
});
