import { makeHarness, NORMAL_PATHS } from '../helpers';
import { parseIp } from '../../src/common/ip.util';
import { RedisService } from '../../src/redis/redis.service';
import { ReputationService } from '../../src/reputation/reputation.service';
import { ConfigService } from '../../src/config/config.service';
import { testEnv } from '../helpers';

const SCANNER = ['/.env', '/.git/config', '/shell.php', '/phpinfo.php', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'];

describe('Escenarios de decisión (punto 52)', () => {
  it('visitante normal: siempre ALLOW', async () => {
    const h = await makeHarness();
    for (const uri of NORMAL_PATHS) {
      const d = await h.scoring.decide(h.req({ ip: '198.51.100.30', uri }));
      expect(d.action).toBe('ALLOW');
    }
  });

  it('empresa NAT: 500 peticiones legítimas desde una sola IP no provocan ban', async () => {
    const h = await makeHarness();
    const uas = Array.from({ length: 40 }, (_, i) => `Mozilla/5.0 (Windows NT 10.0) Chrome/12${i}.0 Safari/537.36`);
    for (let i = 0; i < 500; i++) {
      const d = await h.scoring.decide(h.req({ ip: '203.0.113.10', uri: NORMAL_PATHS[i % NORMAL_PATHS.length]!, userAgent: uas[i % uas.length]! }));
      expect(d.action).toBe('ALLOW');
    }
    expect(await h.bans.getBan('ip', '203.0.113.10')).toBeNull();
  });

  it('WooCommerce: 400 wc-ajax legítimos no provocan ban', async () => {
    const h = await makeHarness();
    for (let i = 0; i < 400; i++) {
      const uri = i % 2 ? '/?wc-ajax=get_refreshed_fragments' : '/?wc-ajax=update_order_review';
      const d = await h.scoring.decide(h.req({ ip: '203.0.113.11', uri, method: 'POST' }));
      expect(d.action).toBe('ALLOW');
    }
  });

  it('admin-ajax normal (heartbeat, Elementor): no ban', async () => {
    const h = await makeHarness();
    for (let i = 0; i < 300; i++) {
      const uri = i % 2 ? '/wp-admin/admin-ajax.php' : '/site2/wp-admin/admin-ajax.php';
      const d = await h.scoring.decide(h.req({ ip: '203.0.113.12', uri, method: 'POST' }));
      expect(d.action).toBe('ALLOW');
    }
  });

  it('WordPress Multisite: /site1/wp-admin/ y /site2/wp-admin/ funcionan', async () => {
    const h = await makeHarness();
    for (const uri of ['/site1/wp-admin/', '/site2/wp-admin/', '/site1/wp-login.php', '/site2/wp-admin/post-new.php', '/site1/wp-json/wp/v2/posts']) {
      expect((await h.scoring.decide(h.req({ ip: '203.0.113.13', uri }))).action).toBe('ALLOW');
    }
  });

  it('scanner (ENFORCE): .env/.git/shell/phpinfo/phpunit → ban rápido', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'false' });
    const actions: string[] = [];
    for (const uri of SCANNER) actions.push((await h.scoring.decide(h.req({ ip: '192.0.2.50', uri, userAgent: 'python-requests/2.31' }))).action);
    expect(actions).toContain('BLOCK');
    const firstBlock = actions.indexOf('BLOCK');
    expect(firstBlock).toBeLessThanOrEqual(3);
    const ban = await h.bans.getBan('ip', '192.0.2.50');
    expect(ban).not.toBeNull();
    expect(ban!.durationSec).toBe(900); // primer ban 15 min
    // Tras el ban, incluso una petición normal se bloquea
    const after = await h.scoring.decide(h.req({ ip: '192.0.2.50', uri: '/' }));
    expect(after.action).toBe('BLOCK');
    expect(after.basis).toBe('banned');
    // Explicabilidad
    const state = await h.reputation.call((s) => s.getIpState('192.0.2.50'));
    const all = state!.reasons.map((r) => r.reason).join(',');
    expect(all).toContain('env-scan+25');
    expect(all).toContain('git-scan+25');
    expect(all).toContain('rapid_scanning+20');
  });

  it('reincidencia: la duración escala 15m → 1h → 6h', async () => {
    const h = await makeHarness();
    const ip = parseIp('192.0.2.60')!;
    const d1 = await h.bans.ban({ ip, ipKey: ip.address, scope: 'ip', key: ip.address, reason: 't', reasons: [], score: 90, source: 'NGINX', audit: false });
    const d2 = await h.bans.ban({ ip, ipKey: ip.address, scope: 'ip', key: ip.address, reason: 't', reasons: [], score: 90, source: 'NGINX', audit: false });
    const d3 = await h.bans.ban({ ip, ipKey: ip.address, scope: 'ip', key: ip.address, reason: 't', reasons: [], score: 90, source: 'NGINX', audit: false });
    expect([d1.durationSec, d2.durationSec, d3.durationSec]).toEqual([900, 3600, 21600]);
  });

  it('AUDIT: calcula WOULD_BLOCK pero no bloquea ni crea ban real', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true' });
    let last;
    for (const uri of SCANNER) last = await h.scoring.decide(h.req({ ip: '192.0.2.51', uri }));
    expect(last!.audit).toBe(true);
    expect(last!.action).toBe('BLOCK'); // lo que HARÍA
    expect(await h.bans.getBan('ip', '192.0.2.51', false)).toBeNull(); // ban real: no
    expect(await h.bans.getBan('ip', '192.0.2.51', true)).not.toBeNull(); // would-ban: sí
  });

  it('IPv6: el ban cubre el /64 completo', async () => {
    const h = await makeHarness();
    for (const uri of SCANNER) await h.scoring.decide(h.req({ ip: '2001:db8:aaaa:1::10', uri }));
    const other = await h.scoring.decide(h.req({ ip: '2001:db8:aaaa:1:ffff::99', uri: '/' }));
    expect(other.action).toBe('BLOCK');
    const outside = await h.scoring.decide(h.req({ ip: '2001:db8:aaaa:2::10', uri: '/' }));
    expect(outside.action).toBe('ALLOW');
  });

  it('señales de baja confianza solo afectan a la huella IP+UA (NAT seguro)', async () => {
    const h = await makeHarness();
    // Mismo usuario raro: sin UA + ?author=N muchas veces (baja confianza)
    let d;
    for (let i = 1; i <= 30; i++) d = await h.scoring.decide(h.req({ ip: '203.0.113.20', uri: `/?author=${i}`, userAgent: '' }));
    expect(d!.action).toBe('BLOCK');
    expect(d!.basis).toMatch(/fp/);
    expect(await h.bans.getBan('ip', '203.0.113.20')).toBeNull(); // la IP NO está baneada
    // Otro empleado detrás del mismo NAT con navegador normal: sin afectar
    const other = await h.scoring.decide(h.req({ ip: '203.0.113.20', uri: '/shop/' }));
    expect(other.action).toBe('ALLOW');
  });

  it('señales medias sin evidencia fuerte nunca banean la IP entera', async () => {
    const h = await makeHarness();
    // XSS (medium) repetido desde muchos UAs distintos (NAT): la IP puede limitarse pero no banearse
    for (let i = 0; i < 12; i++) {
      await h.scoring.decide(h.req({ ip: '203.0.113.21', uri: `/?q=<script>alert(${i})</script>`, userAgent: `UA-${i}` }));
    }
    expect(await h.bans.getBan('ip', '203.0.113.21')).toBeNull();
  });

  it('Googlebot FALSO (UA dice Googlebot, IP no valida) no queda verificado', async () => {
    const h = await makeHarness();
    h.resolver.ptr.set('192.0.2.70', ['evil.example.net']);
    const b = h.req({ ip: '192.0.2.70', uri: '/', userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' });
    const d1 = await h.scoring.decide(b);
    expect(d1.basis).not.toMatch(/verified-bot/);
    await h.bots.drain();
    const d2 = await h.scoring.decide(b);
    expect(d2.basis).not.toMatch(/verified-bot/);
    expect(d2.reasons.join(',')).toContain('fake-bot:google');
  });

  it('Googlebot FALSO con PTR falsificado (hostname googlebot.com que no resuelve a la IP)', async () => {
    const h = await makeHarness();
    h.resolver.ptr.set('192.0.2.71', ['crawl-1-2-3-4.googlebot.com']);
    h.resolver.a.set('crawl-1-2-3-4.googlebot.com', ['66.249.66.1']);
    expect(await h.bots.verify('192.0.2.71', ['googlebot.com'])).toBe(false);
  });

  it('Googlebot REAL (FCrDNS correcto) queda verificado y nunca se bloquea', async () => {
    const h = await makeHarness();
    h.resolver.ptr.set('66.249.66.1', ['crawl-66-249-66-1.googlebot.com.']);
    h.resolver.a.set('crawl-66-249-66-1.googlebot.com', ['66.249.66.1']);
    const b = h.req({ ip: '66.249.66.1', uri: '/', userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' });
    await h.scoring.decide(b);
    await h.bots.drain();
    const d = await h.scoring.decide(b);
    expect(d.basis).toBe('verified-bot:google');
    // aunque siga un enlace raro, nunca se bloquea
    const weird = await h.scoring.decide(h.req({ ip: '66.249.66.1', uri: '/.env', userAgent: b.ctx.userAgent }));
    expect(weird.action).toBe('ALLOW');
  });

  it('Googlebot IPv6 real verificado', async () => {
    const h = await makeHarness();
    h.resolver.ptr.set('2001:4860:4801:10::1', ['crawl-2001-4860-4801-10--1.googlebot.com']);
    h.resolver.aaaa.set('crawl-2001-4860-4801-10--1.googlebot.com', ['2001:4860:4801:10::1']);
    expect(await h.bots.verify('2001:4860:4801:10::1', ['googlebot.com'])).toBe(true);
  });

  it('IP de ADMIN_ALLOWLIST nunca se bloquea (pero se registra)', async () => {
    const h = await makeHarness({ ADMIN_ALLOWLIST: '203.0.113.36/32,2001:db8:ad::/48' });
    for (const uri of SCANNER) {
      const d = await h.scoring.decide(h.req({ ip: '203.0.113.36', uri }));
      expect(d.action).toBe('ALLOW');
      expect(d.basis).toBe('allowlist:ADMIN_ALLOWLIST');
    }
    expect((await h.scoring.decide(h.req({ ip: '2001:db8:ad:1::5', uri: '/.env' }))).action).toBe('ALLOW');
  });

  it('regla action=block corta la petición aunque el score no llegue al umbral', async () => {
    const h = await makeHarness();
    const d = await h.scoring.decide(h.req({ ip: '192.0.2.80', uri: '/?x=${jndi:ldap://a/b}' }));
    expect(d.action).toBe('BLOCK');
  });

  it('score decae con el tiempo (no queda marcado para siempre)', async () => {
    const h = await makeHarness({ SCORE_DECAY_PER_MINUTE: '2' });
    const now = Date.now();
    const p = h.scoring.params();
    await h.reputation.memory.apply(
      { ipKey: '192.0.2.90', fpKey: 'f', now: now - 30 * 60_000, ipDelta: 70, fpDelta: 70, strongDelta: 70, isHit: true, reason: 'x+70', ipTtlSec: 7200, fpTtlSec: 7200, country: '', audit: false },
      p,
    );
    const r = await h.reputation.memory.apply(
      { ipKey: '192.0.2.90', fpKey: 'f', now, ipDelta: 0, fpDelta: 0, strongDelta: 0, isHit: false, reason: '', ipTtlSec: 7200, fpTtlSec: 7200, country: '', audit: false },
      p,
    );
    expect(r.ipScore).toBeCloseTo(10, 0); // 70 - 30 min × 2
  });

  it('Redis caído: SmartGuard sigue decidiendo en memoria (no tumba WooCommerce)', async () => {
    const env = testEnv({ REDIS_ENABLED: 'true', REDIS_HOST: '127.0.0.1', REDIS_PORT: '1' });
    const config = new ConfigService(env);
    const redis = new RedisService(config);
    const rep = new ReputationService(redis);
    expect(rep.store.kind).toBe('memory');
    const h = await makeHarness();
    // Reemplazar el almacén por uno que siempre falla → fail-open
    (h.reputation as unknown as { call: () => Promise<never> }).call = async () => {
      throw new Error('redis down');
    };
    const d = await h.scoring.decide(h.req({ ip: '198.51.100.99', uri: '/checkout/' }));
    expect(d.action).toBe('ALLOW');
    expect(d.basis).toBe('error-fail-open');
    // cerrar el cliente ioredis y esperar su fin (evita handles abiertos en Jest)
    await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, 3000);
      redis.client!.once('end', () => {
        clearTimeout(t);
        resolve();
      });
      redis.client!.disconnect();
    });
  });
});

describe('Analizador de logs', () => {
  const line = (o: Record<string, unknown>) => ({ ts: new Date().toISOString(), h: 'orleansembroidery.com', ua: 'Mozilla/5.0', m: 'GET', ...o });

  it('credential stuffing: muchos POST wp-login fallidos (200) se detectan', async () => {
    const h = await makeHarness();
    for (let i = 0; i < 60; i++) h.analyzer.processLine(line({ ip: '192.0.2.100', m: 'POST', p: '/wp-login.php', st: 200, php: '127.0.0.1:9000', sg: 'ALLOW' }));
    await h.analyzer.flush();
    const s = await h.reputation.call((x) => x.getIpState('192.0.2.100'));
    expect(s).not.toBeNull();
    expect(s!.reasons.map((r) => r.reason).join(',')).toContain('credential_stuffing');
    expect(s!.strong).toBeGreaterThanOrEqual(40);
  });

  it('logins exitosos (302) no suman', async () => {
    const h = await makeHarness();
    for (let i = 0; i < 60; i++) h.analyzer.processLine(line({ ip: '192.0.2.101', m: 'POST', p: '/wp-login.php', st: 302, php: '127.0.0.1:9000', sg: 'ALLOW' }));
    await h.analyzer.flush();
    expect(await h.reputation.call((x) => x.getIpState('192.0.2.101'))).toBeNull();
  });

  it('peticiones cortadas por Nginx (sin sg) aplican reglas de ruta', async () => {
    const h = await makeHarness();
    h.analyzer.processLine(line({ ip: '192.0.2.102', p: '/.env', st: 403, php: '' }));
    await h.analyzer.flush();
    const s = await h.reputation.call((x) => x.getIpState('192.0.2.102'));
    expect(s!.reasons[0]!.reason).toContain('env-scan+25');
    expect(s!.reasons[0]!.reason).toContain('nginx_denied+3');
  });

  it('no duplica reglas si la petición ya pasó por auth_request (sg presente)', async () => {
    const h = await makeHarness();
    h.analyzer.processLine(line({ ip: '192.0.2.103', p: '/shell.php', st: 404, php: '', sg: 'ALLOW' }));
    await h.analyzer.flush();
    const s = await h.reputation.call((x) => x.getIpState('192.0.2.103'));
    const r = s!.reasons[0]!.reason;
    expect(r).not.toContain('webshell-scan');
    expect(r).toContain('php_not_found+10');
  });

  it('enumeración de plugins (10 plugins distintos con 404) → WP_SCAN', async () => {
    const h = await makeHarness();
    for (let i = 0; i < 12; i++) h.analyzer.processLine(line({ ip: '192.0.2.104', p: `/wp-content/plugins/plugin${i}/readme.txt`, st: 404, php: '' }));
    await h.analyzer.flush();
    const s = await h.reputation.call((x) => x.getIpState('192.0.2.104'));
    expect(s!.reasons.map((r) => r.reason).join(',')).toContain('plugin_enumeration+20');
  });

  it('404 normales de un visitante no le penalizan de forma relevante', async () => {
    const h = await makeHarness();
    for (let i = 0; i < 3; i++) h.analyzer.processLine(line({ ip: '192.0.2.105', p: `/product/viejo-${i}/`, st: 404, php: '127.0.0.1:9000', sg: 'ALLOW' }));
    await h.analyzer.flush();
    const d = await h.scoring.decide(h.req({ ip: '192.0.2.105', uri: '/' }));
    expect(d.action).toBe('ALLOW');
  });
});
