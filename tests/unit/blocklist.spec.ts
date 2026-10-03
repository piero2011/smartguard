import { makeHarness } from '../helpers';
import { normalizeBotPattern } from '../../src/blocklist/blocklist.service';
import { parseIp } from '../../src/common/ip.util';

const DOTBOT = 'Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot; help@moz.com)';

describe('Bloqueos manuales (panel): se aplican también en AUDIT', () => {
  it('normaliza el texto del bot y rechaza lo que no es válido', () => {
    expect(normalizeBotPattern('  DotBot ')).toBe('dotbot');
    expect(normalizeBotPattern('python-requests/2.31')).toBe('python-requests/2.31');
    expect(normalizeBotPattern('ab')).toBeNull();
    expect(normalizeBotPattern('bot(.*)')).toBeNull();
    expect(normalizeBotPattern('x'.repeat(65))).toBeNull();
  });

  it('bot bloqueado por nombre: BLOCK real en AUDIT, desde cualquier IP', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true' });
    const before = await h.scoring.decide(h.req({ ip: '198.51.100.40', userAgent: DOTBOT }));
    expect(before.action).not.toBe('BLOCK');

    await h.blocklist.addBot('DotBot', 'test');
    for (const ip of ['198.51.100.40', '203.0.113.77', '2001:db8:1::5']) {
      const d = await h.scoring.decide(h.req({ ip, userAgent: DOTBOT }));
      expect(d).toMatchObject({ action: 'BLOCK', audit: false, basis: 'manual:bot' });
      expect(d.reasons).toContain('manual-bot:dotbot');
    }
    // un navegador normal desde la misma IP no se ve afectado
    const normal = await h.scoring.decide(h.req({ ip: '198.51.100.40' }));
    expect(normal.action).toBe('ALLOW');
  });

  it('quitar el bot lo desbloquea', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true' });
    await h.blocklist.addBot('dotbot', '');
    expect(h.blocklist.listBots().map((b) => b.pattern)).toEqual(['dotbot']);
    await h.blocklist.removeBot('DotBot');
    expect(h.blocklist.listBots()).toEqual([]);
    const d = await h.scoring.decide(h.req({ ip: '198.51.100.41', userAgent: DOTBOT }));
    expect(d.action).not.toBe('BLOCK');
    await expect(h.blocklist.removeBot('dotbot')).rejects.toMatchObject({ response: { code: 'BOT_NOT_BLOCKED' } });
  });

  it('rechaza textos que también cubren navegadores, buscadores o WordPress', async () => {
    const h = await makeHarness();
    for (const p of ['Mozilla', 'chrome', 'Safari', 'applewebkit', 'googlebot', 'bingbot', 'wordpress', 'android', 'bot']) {
      await expect(h.blocklist.addBot(p, '')).rejects.toMatchObject({ response: { code: 'BOT_PATTERN_TOO_GENERIC' } });
    }
    await expect(h.blocklist.addBot('a b', '')).resolves.toMatchObject({ pattern: 'a b' });
    await expect(h.blocklist.addBot('<script>', '')).rejects.toMatchObject({ response: { code: 'INVALID_BOT_PATTERN' } });
  });

  it('rechaza duplicados y textos ya cubiertos por otro', async () => {
    const h = await makeHarness();
    await h.blocklist.addBot('dotbot', '');
    await expect(h.blocklist.addBot('DOTBOT', '')).rejects.toMatchObject({ response: { code: 'BOT_ALREADY_BLOCKED' } });
    await expect(h.blocklist.addBot('dotbot/1.2', '')).rejects.toMatchObject({ response: { code: 'BOT_ALREADY_BLOCKED' } });
  });

  it('una IP de la lista blanca nunca se bloquea, aunque use el User-Agent bloqueado', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true', ADMIN_ALLOWLIST: '192.0.2.200' });
    await h.blocklist.addBot('dotbot', '');
    const d = await h.scoring.decide(h.req({ ip: '192.0.2.200', userAgent: DOTBOT }));
    expect(d.action).toBe('ALLOW');
  });

  it('ban manual de IP: BLOCK real en AUDIT; los bans automáticos siguen en suspenso', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true' });
    const ban = (addr: string, source: 'MANUAL' | 'NGINX') => {
      const ip = parseIp(addr)!;
      return h.bans.ban({ ip, ipKey: ip.address, scope: 'ip', key: ip.address, reason: 't', reasons: ['t'], score: 0, source, audit: false, durationSec: 3600 });
    };
    await ban('198.51.100.50', 'MANUAL');
    await ban('198.51.100.51', 'NGINX');
    await h.blocklist.refresh();

    const manual = await h.scoring.decide(h.req({ ip: '198.51.100.50' }));
    expect(manual).toMatchObject({ action: 'BLOCK', audit: false, basis: 'manual:ip' });
    const auto = await h.scoring.decide(h.req({ ip: '198.51.100.51' }));
    expect(auto.audit).toBe(true);

    await h.bans.unban(parseIp('198.51.100.50')!, '198.51.100.50');
    await h.blocklist.refresh();
    const after = await h.scoring.decide(h.req({ ip: '198.51.100.50' }));
    expect(after.action).not.toBe('BLOCK');
  });

  it('el analizador de logs no aplica bloqueos manuales (solo la decisión en línea)', async () => {
    const h = await makeHarness({ AUDIT_MODE: 'true' });
    await h.blocklist.addBot('dotbot', '');
    const d = await h.scoring.evaluate(h.req({ ip: '198.51.100.60', userAgent: DOTBOT }), [], { source: 'analyzer' });
    expect(d.action).toBe('ALLOW');
  });
});
