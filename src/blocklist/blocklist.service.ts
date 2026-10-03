import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ApiError } from '../common/api-error';
import { logger } from '../common/logger';
import { BanService } from '../ban/ban.service';
import { ReputationService } from '../reputation/reputation.service';
import { BlockedBot, BlockedNetwork } from '../reputation/reputation.store';
import { IpInfoService } from '../ipinfo/ipinfo.service';
import { IpRangeSet } from '../common/ip-range-set';
import { ParsedIp, parseCidr } from '../common/ip.util';

/** Bloqueo manual que coincide con una petición. */
export interface ManualBlock {
  kind: 'ip' | 'bot' | 'net';
  /** Motivo que se registra en el evento: "manual-ip", "manual-bot:<texto>" o "manual-net:AS<n>" */
  id: string;
}

/** Descarga los rangos (CIDR) que anuncia un ASN. */
export type PrefixFetcher = (asn: number) => Promise<string[]>;

/** Red bloqueada tal como la ve el panel (sin la lista completa de rangos). */
export interface BlockedNetworkView {
  asn: number;
  org: string;
  country: string;
  prefixCount: number;
  note: string;
  createdAt: number;
  fetchedAt: number;
}

/** Redes que nunca se pueden bloquear: Cloudflare es el proxy por el que llegan todos los visitantes. */
const PROTECTED_ASNS = new Set([13335, 209242]);
const MAX_PREFIXES = 20_000;
const DAY_MS = 86_400_000;

/**
 * Rangos anunciados por un ASN según RIPEstat (API pública, sin clave). Solo se llama al bloquear
 * una red y una vez al día para refrescarla; nunca en el camino de la decisión.
 */
export const ripeStatPrefixes: PrefixFetcher = async (asn) => {
  const res = await fetch(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`, {
    headers: { accept: 'application/json', 'user-agent': 'smartguard' },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`RIPEstat HTTP ${res.status}`);
  const body = (await res.json()) as { data?: { prefixes?: { prefix?: unknown }[] } };
  return (body.data?.prefixes ?? []).map((p) => String(p.prefix ?? ''));
};

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
 * Bloqueos manuales decididos desde el panel/API: IPs (bans con source MANUAL), bots por nombre
 * (texto del User-Agent) y redes completas (todos los rangos de un ASN, p. ej. un proveedor de
 * hosting). Son decisiones explícitas del administrador, así que se aplican SIEMPRE, también en
 * AUDIT: AUDIT solo deja en suspenso lo que SmartGuard decide por su cuenta.
 *
 * match() es síncrono y sin I/O (el camino de la decisión no añade ninguna consulta a Redis): las
 * listas se mantienen en memoria y se refrescan cada 15 s y tras cada cambio por la API.
 * Los bans manuales de IP solo hacen falta aquí para AUDIT; en ENFORCE ya los aplica el ban normal.
 */
@Injectable()
export class BlocklistService implements OnModuleInit, OnModuleDestroy {
  private bots: BlockedBot[] = [];
  /** clave de IP → expiración del ban manual */
  private ips = new Map<string, number>();
  private networks: BlockedNetwork[] = [];
  /** IP → ASN bloqueado (búsqueda binaria sobre los rangos de todas las redes bloqueadas) */
  private netSet = new IpRangeSet<number>();
  private netSig = '';
  private timers: NodeJS.Timeout[] = [];
  private fetchPrefixes: PrefixFetcher = ripeStatPrefixes;

  constructor(
    private readonly reputation: ReputationService,
    private readonly bans: BanService,
    private readonly ipinfo: IpInfoService,
  ) {}

  /** Solo tests */
  setPrefixFetcher(f: PrefixFetcher): void {
    this.fetchPrefixes = f;
  }

  async onModuleInit(): Promise<void> {
    await this.refresh();
    const t1 = setInterval(() => void this.refresh(), 15_000);
    const t2 = setInterval(() => void this.refreshNetworkPrefixes(), DAY_MS);
    t1.unref();
    t2.unref();
    this.timers.push(t1, t2);
    void this.refreshNetworkPrefixes();
  }

  onModuleDestroy(): void {
    for (const t of this.timers) clearInterval(t);
  }

  async refresh(): Promise<void> {
    // Con Redis caído el almacén en memoria está vacío: se conserva lo último conocido.
    if (this.reputation.degraded) return;
    try {
      const [bots, bans, networks] = await Promise.all([
        this.reputation.call((s) => s.listBlockedBots()),
        this.bans.list(false, 0, 1000),
        this.reputation.call((s) => s.listBlockedNetworks()),
      ]);
      const ips = new Map<string, number>();
      for (const b of bans) if (b.source === 'MANUAL' && b.scope === 'ip') ips.set(b.key, b.expiresAt);
      this.bots = bots;
      this.ips = ips;
      this.setNetworks(networks);
    } catch (e) {
      logger.warn(`No se pudieron refrescar los bloqueos manuales: ${(e as Error).message}`, 'Blocklist');
    }
  }

  /** Reconstruye el índice de rangos solo si la lista de redes (o sus rangos) cambió. */
  private setNetworks(networks: BlockedNetwork[]): void {
    const sig = networks.map((n) => `${n.asn}:${n.fetchedAt}:${n.prefixes.length}`).sort().join(',');
    this.networks = networks;
    if (sig === this.netSig) return;
    this.netSig = sig;
    this.netSet = new IpRangeSet(networks.flatMap((n) => n.prefixes.map((cidr) => ({ cidr, tag: n.asn }))));
  }

  /** ¿Esta petición está bloqueada a mano? Síncrono, sin I/O. */
  match(ipKey: string, userAgent: string, now = Date.now(), ip?: ParsedIp): ManualBlock | null {
    const exp = this.ips.get(ipKey);
    if (exp !== undefined && exp > now) return { kind: 'ip', id: 'manual-ip' };
    if (ip && this.netSet.size > 0) {
      const asn = this.netSet.find(ip);
      if (asn !== null) return { kind: 'net', id: `manual-net:AS${asn}` };
    }
    if (this.bots.length === 0 || !userAgent) return null;
    const ua = userAgent.toLowerCase();
    for (const b of this.bots) {
      if ((!b.expiresAt || b.expiresAt > now) && ua.includes(b.pattern)) return { kind: 'bot', id: `manual-bot:${b.pattern}` };
    }
    return null;
  }

  // --- Redes completas (ASN) ------------------------------------------------------------------

  listNetworks(): BlockedNetworkView[] {
    return this.networks
      .map((n) => ({ asn: n.asn, org: n.org, country: n.country, prefixCount: n.prefixes.length, note: n.note, createdAt: n.createdAt, fetchedAt: n.fetchedAt }))
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  /** Descarga y valida los rangos de un ASN. Lanza si la fuente falla o no devuelve ninguno. */
  private async prefixesOf(asn: number): Promise<string[]> {
    const raw = await this.fetchPrefixes(asn);
    const out = new Set<string>();
    for (const p of raw.slice(0, MAX_PREFIXES)) {
      const c = parseCidr(p);
      // mismos mínimos que IpRangeSet: un prefijo absurdamente amplio no se guarda ni se cuenta
      if (c && c.range[1] >= (c.version === 4 ? 8 : 16)) out.add(c.text);
    }
    if (out.size === 0) throw new Error('sin rangos');
    return [...out];
  }

  /**
   * Bloquea la red entera a la que pertenece una IP (o un ASN dado): todos los rangos que anuncia.
   * Nunca bloquea Cloudflare, y las IPs de la lista blanca y los buscadores verificados siguen pasando.
   */
  async addNetwork(target: { ip?: string; asn?: number }, note: string): Promise<BlockedNetworkView> {
    let asn = target.asn ?? null;
    let org = '';
    let country = '';
    if (asn === null) {
      const info = target.ip ? await this.ipinfo.lookup(target.ip) : null;
      if (!info?.asn) throw new ApiError(400, 'NETWORK_UNKNOWN', `Could not find the network of ${target.ip ?? '?'}`, { ip: target.ip ?? '' });
      ({ asn, org, country } = info);
    } else {
      org = await this.ipinfo.asnName(asn);
    }
    if (asn === null) throw new ApiError(400, 'NETWORK_UNKNOWN', 'Unknown network', {});
    if (PROTECTED_ASNS.has(asn)) {
      throw new ApiError(400, 'NETWORK_PROTECTED', `AS${asn} is Cloudflare: blocking it would block all your visitors`, { asn, org: org || 'Cloudflare' });
    }
    if (this.networks.some((n) => n.asn === asn)) {
      throw new ApiError(409, 'NETWORK_ALREADY_BLOCKED', `AS${asn} is already blocked`, { asn, org });
    }
    let prefixes: string[];
    try {
      prefixes = await this.prefixesOf(asn);
    } catch (e) {
      throw new ApiError(502, 'NETWORK_FETCH_FAILED', `Could not download the ranges of AS${asn}: ${(e as Error).message}`, { asn, org });
    }
    const now = Date.now();
    const entry: BlockedNetwork = { asn, org: org || `AS${asn}`, country, prefixes, note: note.slice(0, 200), createdAt: now, fetchedAt: now };
    await this.reputation.call((s) => s.setBlockedNetwork(entry));
    await this.refresh();
    logger.log(`Red bloqueada: AS${asn} ${entry.org} (${prefixes.length} rangos)`, 'Blocklist');
    return this.listNetworks().find((n) => n.asn === asn)!;
  }

  async removeNetwork(asn: number): Promise<boolean> {
    const ok = await this.reputation.call((s) => s.deleteBlockedNetwork(asn));
    if (!ok) throw new ApiError(404, 'NETWORK_NOT_BLOCKED', `AS${asn} is not in the blocked networks list`, { asn });
    await this.refresh();
    return true;
  }

  /** Vuelve a descargar los rangos de las redes bloqueadas con más de un día (los ASN ganan y pierden rangos). */
  async refreshNetworkPrefixes(now = Date.now()): Promise<void> {
    for (const n of this.networks) {
      if (now - n.fetchedAt < DAY_MS) continue;
      try {
        const prefixes = await this.prefixesOf(n.asn);
        await this.reputation.call((s) => s.setBlockedNetwork({ ...n, prefixes, fetchedAt: now }));
      } catch (e) {
        // Se conservan los rangos anteriores: mejor una lista de ayer que ninguna.
        logger.warn(`No se pudieron actualizar los rangos de AS${n.asn}: ${(e as Error).message}`, 'Blocklist');
      }
    }
    await this.refresh();
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
