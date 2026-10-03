import 'reflect-metadata';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Test } from '@nestjs/testing';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { AppModule } from '../../src/app.module';
import { ConfigService } from '../../src/config/config.service';
import { configureApp, createAdapter } from '../../src/main';
import { testEnv } from '../helpers';

const SECRET = 'test-decision-secret-0123456789';
const TOKEN = 'test-admin-token-0123456789abcdef0123456789';

async function makeApp(dir: string): Promise<NestFastifyApplication> {
  const config = new ConfigService(testEnv({ AUDIT_MODE: 'false', ANALYZER_STATE_FILE: path.join(dir, 'analyzer.state') }));
  await config.loadFiles();
  const mod = await Test.createTestingModule({ imports: [AppModule.forRoot({ config })] }).compile();
  const app = mod.createNestApplication<NestFastifyApplication>(createAdapter());
  configureApp(app);
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
  return app;
}

describe('Reglas creadas desde el panel', () => {
  let dir: string;
  let app: NestFastifyApplication;
  const auth = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };
  const admin = (method: 'GET' | 'POST' | 'DELETE', url: string, payload?: unknown) =>
    app.inject({ method, url, headers: payload ? auth : { authorization: auth.authorization }, payload: payload as object, remoteAddress: '127.0.0.1' });
  const decide = (ip: string, uri: string) =>
    app.inject({
      method: 'GET',
      url: '/internal/decision',
      headers: {
        'x-smartguard-key': SECRET,
        'x-real-ip': ip,
        'x-tcp-ip': '172.64.1.1',
        'x-original-uri': uri,
        'x-original-method': 'GET',
        'x-user-agent': 'Mozilla/5.0 Test',
        'x-host': 'orleansembroidery.com',
        'x-request-id': 'abcdef0123456789',
      },
      remoteAddress: '127.0.0.1',
    });
  const rule = {
    id: 'mi-panel-oculto',
    name: 'Panel que no uso',
    target: 'path',
    pattern: '^/panel-secreto(?:/|$)',
    score: 30,
    severity: 'high',
    confidence: 'high',
    category: 'SCANNER',
    action: 'block',
  };

  beforeAll(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sg-rules-'));
    app = await makeApp(dir);
  });
  afterAll(async () => {
    await app.close();
    await fs.rm(dir, { recursive: true });
  });

  it('una regla nueva bloquea al momento, sin reiniciar, y queda guardada', async () => {
    expect((await decide('198.51.100.201', '/panel-secreto/')).statusCode).toBe(200);
    const r = await admin('POST', '/admin/panel-rules', rule);
    expect(r.statusCode).toBe(200);
    expect((await decide('198.51.100.202', '/panel-secreto/')).statusCode).toBe(403);
    expect((await decide('198.51.100.203', '/shop/')).statusCode).toBe(200);
    expect((await admin('GET', '/admin/panel-rules')).json().items.map((x: { id: string }) => x.id)).toEqual(['mi-panel-oculto']);
    const all = (await admin('GET', '/admin/rules')).json().rules as { id: string; source: string }[];
    expect(all.find((x) => x.id === 'mi-panel-oculto')!.source).toBe('panel');
    expect(all.find((x) => x.id === 'env-scan')!.source).toBe('file');
    expect(JSON.parse(await fs.readFile(path.join(dir, 'panel-rules.json'), 'utf8')).rules).toHaveLength(1);
  });

  it('rechaza lo peligroso: patrón que alcanza tráfico normal, regex insegura, id de una regla interna', async () => {
    const broad = await admin('POST', '/admin/panel-rules', { ...rule, id: 'demasiado-amplia', pattern: '^/' });
    expect(broad.statusCode).toBe(400);
    expect(broad.json().code).toBe('RULE_TOO_BROAD');
    const redos = await admin('POST', '/admin/panel-rules', { ...rule, id: 'regex-mala', pattern: '(a+)+$' });
    expect(redos.json().code).toBe('RULE_REJECTED');
    expect((await admin('POST', '/admin/panel-rules', { ...rule, id: 'env-scan' })).json().code).toBe('RULE_ID_TAKEN');
    expect((await admin('POST', '/admin/panel-rules', { ...rule, id: 'ID Con Espacios' })).statusCode).toBe(400);
    // nada de lo rechazado quedó activo ni guardado
    expect((await admin('GET', '/admin/panel-rules')).json().items).toHaveLength(1);
    expect((await decide('198.51.100.204', '/')).statusCode).toBe(200);
  });

  it('una excepción (allow) sí puede ser amplia; desactivar y borrar surten efecto al momento', async () => {
    expect((await admin('POST', '/admin/panel-rules', { ...rule, enabled: false })).statusCode).toBe(200);
    expect((await decide('198.51.100.205', '/panel-secreto/')).statusCode).toBe(200);
    expect((await admin('POST', '/admin/panel-rules', { ...rule, enabled: true })).statusCode).toBe(200);
    expect((await decide('198.51.100.206', '/panel-secreto/')).statusCode).toBe(403);
    const exception = { id: 'mi-excepcion', target: 'path', pattern: '^/panel-secreto/', score: 0, severity: 'low', category: 'NORMAL', action: 'allow' };
    expect((await admin('POST', '/admin/panel-rules', exception)).statusCode).toBe(200);
    expect((await decide('198.51.100.207', '/panel-secreto/')).statusCode).toBe(200);
    expect((await admin('DELETE', '/admin/panel-rules?id=mi-excepcion')).statusCode).toBe(200);
    expect((await admin('DELETE', '/admin/panel-rules?id=mi-panel-oculto')).statusCode).toBe(200);
    expect((await admin('DELETE', '/admin/panel-rules?id=mi-panel-oculto')).statusCode).toBe(404);
    expect((await decide('198.51.100.208', '/panel-secreto/')).statusCode).toBe(200);
  });

  it('las reglas del panel sobreviven a un reinicio y a una recarga de reglas', async () => {
    expect((await admin('POST', '/admin/panel-rules', rule)).statusCode).toBe(200);
    const second = await makeApp(dir);
    try {
      const r = await second.inject({ method: 'GET', url: '/admin/panel-rules', headers: { authorization: auth.authorization }, remoteAddress: '127.0.0.1' });
      expect(r.json().items.map((x: { id: string }) => x.id)).toEqual(['mi-panel-oculto']);
    } finally {
      await second.close();
    }
    expect((await admin('POST', '/admin/rules/reload')).statusCode).toBe(200);
    expect((await decide('198.51.100.209', '/panel-secreto/')).statusCode).toBe(403);
  });
});
