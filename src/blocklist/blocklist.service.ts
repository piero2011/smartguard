import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ApiError } from '../common/api-error';
import { logger } from '../common/logger';
import { BanService } from '../ban/ban.service';
import { ReputationService } from '../reputation/reputation.service';
import { BlockedBot } from '../reputation/reputation.store';

/** Bloqueo manual que coincide con una petición. */
export interface ManualBlock {
  kind: 'ip' | 'bot';
  /** Motivo que se registra en el evento: "manual-ip" o "manual-bot:<texto>" */
  id: string;
}

const PATTERN_RE = /^[a-z0-9][a-z0-9 ._/:+-]*$/;

/**
 * User-Agents que un texto NUNCA debe cubrir: navegadores reales, bots de buscadores (se verifican
 * por DNS, no por nombre) y el propio WordPress llamándose a sí mismo. Si el texto pedido aparece
 * en alguno, bloquearlo dejaría fuera a visitantes legítimos.
 */
const PROTECTED_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/128.0.0.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0',
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)',
  'WordPress/6.6; https://example.com',
].map((ua) => ua.toLowerCase());

/** Texto a buscar en el User-Agent, normalizado (minúsculas, espacios simples), o null si no es válido. */
export function normalizeBotPattern(input: string): string | null {
  const p = input.trim().replace(/\s+/g, ' ').toLowerCase();
  return p.length >= 3 && p.length <= 64 && PATTERN_RE.test(p) ? p : null;
}

/**
 * Bloqueos manuales decididos desde el panel/API: IPs (bans con source MANUAL) y bots por nombre
 * (texto del User-Agent). Son decisiones explícitas del administrador, así que se aplican SIEMPRE,
 * también en AUDIT: AUDIT solo deja en suspenso lo que SmartGuard decide por su cuenta.
 *
 * match() es síncrono y sin I/O (el camino de la decisión no añade ninguna consulta a Redis): las
 * dos listas se mantienen en memoria y se refrescan cada 15 s y tras cada cambio por la API.
 * Los bans manuales de IP solo hacen falta aquí para AUDIT; en ENFORCE ya los aplica el ban normal.
 */
@Injectable()
export class BlocklistService implements OnModuleInit, OnModuleDestroy {
  private bots: BlockedBot[] = [];
  /** clave de IP → expiración del ban manual */
  private ips = new Map<string, number>();
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly reputation: ReputationService,
    private readonly bans: BanService,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.refresh();
    this.timer = setInterval(() => void this.refresh(), 15_000);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async refresh(): Promise<void> {
    // Con Redis caído el almacén en memoria está vacío: se conserva lo último conocido.
    if (this.reputation.degraded) return;
    try {
      const [bots, bans] = await Promise.all([this.reputation.call((s) => s.listBlockedBots()), this.bans.list(false, 0, 1000)]);
      const ips = new Map<string, number>();
      for (const b of bans) if (b.source === 'MANUAL' && b.scope === 'ip') ips.set(b.key, b.expiresAt);
      this.bots = bots;
      this.ips = ips;
    } catch (e) {
      logger.warn(`No se pudieron refrescar los bloqueos manuales: ${(e as Error).message}`, 'Blocklist');
    }
  }

  /** ¿Esta petición está bloqueada a mano? Síncrono, sin I/O. */
  match(ipKey: string, userAgent: string, now = Date.now()): ManualBlock | null {
    const exp = this.ips.get(ipKey);
    if (exp !== undefined && exp > now) return { kind: 'ip', id: 'manual-ip' };
    if (this.bots.length === 0 || !userAgent) return null;
    const ua = userAgent.toLowerCase();
    for (const b of this.bots) {
      if ((!b.expiresAt || b.expiresAt > now) && ua.includes(b.pattern)) return { kind: 'bot', id: `manual-bot:${b.pattern}` };
    }
    return null;
  }

  listBots(): BlockedBot[] {
    const now = Date.now();
    return this.bots.filter((b) => !b.expiresAt || b.expiresAt > now).sort((a, b) => b.createdAt - a.createdAt);
  }

  async addBot(input: string, note: string, ttlSec?: number): Promise<BlockedBot> {
    const pattern = normalizeBotPattern(input);
    if (!pattern) {
      throw new ApiError(400, 'INVALID_BOT_PATTERN', 'Bot text must be 3-64 characters: letters, digits, space and . _ - / : +', { pattern: input.slice(0, 64) });
    }
    if (PROTECTED_USER_AGENTS.some((ua) => ua.includes(pattern))) {
      throw new ApiError(400, 'BOT_PATTERN_TOO_GENERIC', `"${pattern}" also matches real browsers or search engines; use the bot's own name`, { pattern });
    }
    const covering = this.listBots().find((b) => pattern.includes(b.pattern));
    if (covering) {
      throw new ApiError(409, 'BOT_ALREADY_BLOCKED', `"${pattern}" is already blocked by "${covering.pattern}"`, { pattern, by: covering.pattern });
    }
    const entry: BlockedBot = {
      pattern,
      note: note.slice(0, 200),
      createdAt: Date.now(),
      expiresAt: ttlSec ? Date.now() + ttlSec * 1000 : undefined,
    };
    await this.reputation.call((s) => s.setBlockedBot(entry));
    await this.refresh();
    return entry;
  }

  async removeBot(input: string): Promise<boolean> {
    const pattern = normalizeBotPattern(input);
    if (!pattern) throw new ApiError(400, 'INVALID_BOT_PATTERN', 'Invalid bot text', { pattern: input.slice(0, 64) });
    const ok = await this.reputation.call((s) => s.deleteBlockedBot(pattern));
    if (!ok) throw new ApiError(404, 'BOT_NOT_BLOCKED', `"${pattern}" is not in the blocked bots list`, { pattern });
    await this.refresh();
    return true;
  }
}
