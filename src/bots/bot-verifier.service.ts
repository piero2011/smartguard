import { Injectable } from '@nestjs/common';
import { promises as dnsPromises } from 'node:dns';
import { ConfigService } from '../config/config.service';
import { ReputationService } from '../reputation/reputation.service';
import { TtlMap } from '../reputation/memory.store';
import { ParsedIp, parseIp } from '../common/ip.util';
import { CompiledBot } from '../rules/rules.service';
import { logger } from '../common/logger';
import { DnsResolver, fcrdns } from '../common/dns.util';

export type { DnsResolver } from '../common/dns.util';

export type BotStatus = { state: 'verified'; bot: string } | { state: 'fake'; bot: string } | { state: 'pending' };

/**
 * Verificación de bots por DNS inverso confirmado (FCrDNS, punto 13):
 *
 *   IP → PTR → hostname termina en dominio oficial (googlebot.com, search.msn.com, applebot.apple.com…)
 *      → resolver hostname (A/AAAA) → debe contener la MISMA IP.
 *
 * - NUNCA se hace DNS en el camino síncrono de la decisión: la decisión consulta una caché en memoria;
 *   si no hay dato se encola la verificación y la petición se trata como "no verificada"
 *   (sin privilegios, pero tampoco penalizada).
 * - Resultado cacheado en memoria y en Redis (smartguard:dns:{ip}): positivo 24 h, negativo 6 h.
 * - Concurrencia limitada, cola acotada, deduplicación de consultas en curso.
 */
@Injectable()
export class BotVerifierService {
  private cache = new TtlMap<string>(50_000);
  private inflight = new Set<string>();
  private queue: { ip: string; bot: CompiledBot }[] = [];
  private active = 0;
  private resolver: DnsResolver;
  static readonly MAX_QUEUE = 2_000;
  /** callback cuando se detecta un bot falso (lo registra ScoringService) */
  onFake: ((ip: ParsedIp, bot: CompiledBot) => void) | null = null;
  onVerified: ((ip: ParsedIp, bot: CompiledBot) => void) | null = null;

  constructor(
    private readonly config: ConfigService,
    private readonly reputation: ReputationService,
  ) {
    const r = new dnsPromises.Resolver({ timeout: config.env.dnsTimeoutMs, tries: 1 });
    this.resolver = r;
  }

  /** Solo para tests */
  setResolver(r: DnsResolver): void {
    this.resolver = r;
  }

  /** Consulta SÍNCRONA a caché local. Si no hay dato, encola la verificación. */
  status(ip: ParsedIp, bot: CompiledBot): BotStatus {
    if (bot.verify === 'none') return { state: 'pending' };
    const cached = this.cache.get(`${bot.id}|${ip.address}`);
    if (cached === 'ok') return { state: 'verified', bot: bot.id };
    if (cached === 'fake') return { state: 'fake', bot: bot.id };
    this.enqueue(ip.address, bot);
    return { state: 'pending' };
  }

  private enqueue(ip: string, bot: CompiledBot): void {
    const key = `${bot.id}|${ip}`;
    if (this.inflight.has(key)) return;
    if (this.queue.length >= BotVerifierService.MAX_QUEUE) return;
    this.inflight.add(key);
    this.queue.push({ ip, bot });
    this.pump();
  }

  private pump(): void {
    while (this.active < this.config.env.dnsConcurrency && this.queue.length > 0) {
      const job = this.queue.shift()!;
      this.active++;
      void this.process(job.ip, job.bot).finally(() => {
        this.active--;
        this.inflight.delete(`${job.bot.id}|${job.ip}`);
        this.pump();
      });
    }
  }

  /** Espera a que la cola se vacíe (tests). */
  async drain(): Promise<void> {
    while (this.active > 0 || this.queue.length > 0) await new Promise((r) => setTimeout(r, 5));
  }

  private async process(ip: string, bot: CompiledBot): Promise<void> {
    const key = `${bot.id}|${ip}`;
    const env = this.config.env;
    try {
      const stored = await this.reputation.call((s) => s.getDns(key)).catch(() => null);
      let result: 'ok' | 'fake';
      if (stored === 'ok' || stored === 'fake') {
        result = stored;
      } else {
        result = (await this.verify(ip, bot.domains)) ? 'ok' : 'fake';
        const ttl = result === 'ok' ? env.dnsPositiveTtlSec : env.dnsNegativeTtlSec;
        await this.reputation.call((s) => s.setDns(key, result, ttl)).catch(() => undefined);
      }
      this.cache.set(key, result, (result === 'ok' ? env.dnsPositiveTtlSec : env.dnsNegativeTtlSec) * 1000);
      const parsed = parseIp(ip);
      if (parsed && result === 'fake') this.onFake?.(parsed, bot);
      if (parsed && result === 'ok') this.onVerified?.(parsed, bot);
    } catch (e) {
      // Error de DNS (timeout, SERVFAIL): no concluimos nada; se reintenta más tarde (caché corta).
      this.cache.set(key, 'error', 5 * 60_000);
      logger.debug(`FCrDNS ${ip} (${bot.id}) sin resultado: ${(e as Error).message}`, 'BotVerifier');
    }
  }

  /** FCrDNS puro. true solo si PTR ∈ dominios oficiales Y el hostname resuelve a la misma IP. */
  async verify(ip: string, domains: string[]): Promise<boolean> {
    const patterns = domains.map((d) => ({ text: d, domain: d, wildcard: true }));
    return (await fcrdns(this.resolver, ip, patterns)) !== null;
  }
}
