import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { ReputationService } from '../reputation/reputation.service';
import { MetricsService } from '../metrics/metrics.service';
import { BanRecord } from '../common/types';
import { ParsedIp, isPublicUnicast } from '../common/ip.util';
import { logger } from '../common/logger';

const API = 'https://api.cloudflare.com/client/v4';

interface CfResponse<T> {
  success: boolean;
  errors?: { code: number; message: string }[];
  result?: T;
}

/**
 * Integración OPCIONAL con Cloudflare (punto 15). SmartGuard funciona igual sin ella.
 *
 * Crea "IP Access Rules" (modo block) SOLO cuando:
 *   - ENABLE_CLOUDFLARE=true, modo ENFORCE,
 *   - ban de alcance IP (evidencia fuerte), score ≥ CLOUDFLARE_MIN_SCORE,
 *   - reincidente (banCount ≥ CLOUDFLARE_MIN_BAN_COUNT),
 *   - no existe ya una regla (deduplicación), y no se superan los límites
 *     CLOUDFLARE_MAX_ACTIVE_RULES / CLOUDFLARE_MAX_PER_HOUR.
 *
 * Con CLOUDFLARE_ACCOUNT_ID la regla aplica a TODAS las zonas de la cuenta (recomendado si tienes
 * varios dominios); si no, a CLOUDFLARE_ZONE_ID. Las reglas caducadas se borran con un barrido cada 5 min.
 * Las notas de la regla registran motivo, score, fecha y duración.
 */
@Injectable()
export class CloudflareService implements OnModuleInit, OnModuleDestroy {
  private timer: NodeJS.Timeout | null = null;
  private hourBucket = 0;
  private createdThisHour = 0;
  private chain: Promise<void> = Promise.resolve();

  constructor(
    private readonly config: ConfigService,
    private readonly reputation: ReputationService,
    private readonly metrics: MetricsService,
  ) {}

  get enabled(): boolean {
    return this.config.env.enableCloudflare;
  }

  onModuleInit(): void {
    if (!this.enabled) return;
    this.timer = setInterval(() => void this.sweep(), 5 * 60_000);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private base(): string {
    const e = this.config.env;
    return e.cloudflareAccountId ? `${API}/accounts/${e.cloudflareAccountId}` : `${API}/zones/${e.cloudflareZoneId}`;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<CfResponse<T>> {
    const res = await fetch(`${this.base()}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.config.env.cloudflareApiToken}`,
        'content-type': 'application/json',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });
    const json = (await res.json().catch(() => ({ success: false }))) as CfResponse<T>;
    if (!res.ok || !json.success) {
      const msg = json.errors?.map((e) => `${e.code}:${e.message}`).join('; ') || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return json;
  }

  /** Encola (sin bloquear la decisión) la creación de la regla si se cumplen las condiciones. */
  maybeBlock(ban: BanRecord, ip: ParsedIp): void {
    if (!this.enabled || ban.audit || ban.scope !== 'ip') return;
    const env = this.config.env;
    if (ban.score < env.cloudflareMinScore || ban.banCount < env.cloudflareMinBanCount) return;
    if (!isPublicUnicast(ip)) return;
    this.chain = this.chain.then(() => this.create(ban, ip)).catch(() => undefined);
  }

  private async create(ban: BanRecord, ip: ParsedIp): Promise<void> {
    const env = this.config.env;
    const h = Math.floor(Date.now() / 3_600_000);
    if (h !== this.hourBucket) {
      this.hourBucket = h;
      this.createdThisHour = 0;
    }
    if (this.createdThisHour >= env.cloudflareMaxPerHour) {
      this.metrics.cloudflareBlocks.inc({ result: 'hourly_limit' });
      return;
    }
    const existing = await this.reputation.call((s) => s.getCfRule(ban.key));
    if (existing) return;
    if ((await this.reputation.call((s) => s.countCfRules())) >= env.cloudflareMaxActiveRules) {
      this.metrics.cloudflareBlocks.inc({ result: 'max_active' });
      return;
    }
    if (!(await this.reputation.call((s) => s.once(`cf:${ban.key}`, 300)))) return;

    const isRange = ban.key.includes('/');
    const target = isRange ? 'ip_range' : ip.version === 4 ? 'ip' : 'ip6';
    const notes = `SmartGuard auto-block | score=${Math.round(ban.score)} | reasons=${ban.reasons.slice(0, 5).join(',')} | ` +
      `at=${new Date(ban.createdAt).toISOString()} | until=${new Date(ban.expiresAt).toISOString()} | dur=${ban.durationSec}s`;
    try {
      const res = await this.request<{ id: string }>('POST', '/firewall/access_rules/rules', {
        mode: 'block',
        configuration: { target, value: ban.key },
        notes: notes.slice(0, 500),
      });
      const id = res.result?.id ?? '';
      await this.reputation.call((s) => s.setCfRule(ban.key, id, ban.expiresAt));
      this.createdThisHour++;
      this.metrics.cloudflareBlocks.inc({ result: 'created' });
      logger.event('warn', 'Cloudflare', {
        msg: 'Regla de bloqueo creada en Cloudflare',
        ip: ban.key,
        ruleId: id,
        score: ban.score,
        reason: ban.reason,
        durationSec: ban.durationSec,
        expiresAt: new Date(ban.expiresAt).toISOString(),
      });
    } catch (e) {
      this.metrics.cloudflareBlocks.inc({ result: 'error' });
      logger.warn(`Cloudflare: no se pudo bloquear ${ban.key}: ${(e as Error).message}`, 'Cloudflare');
    }
  }

  /** Elimina la regla asociada a una IP (unban manual). */
  async remove(ipKey: string): Promise<boolean> {
    if (!this.enabled) return false;
    const rule = await this.reputation.call((s) => s.getCfRule(ipKey));
    if (!rule) return false;
    try {
      if (rule.ruleId) await this.request('DELETE', `/firewall/access_rules/rules/${encodeURIComponent(rule.ruleId)}`);
    } catch (e) {
      logger.warn(`Cloudflare: no se pudo borrar la regla ${rule.ruleId}: ${(e as Error).message}`, 'Cloudflare');
      return false;
    }
    await this.reputation.call((s) => s.deleteCfRule(ipKey));
    return true;
  }

  /** Borra reglas caducadas (máx. 50 por barrido para respetar límites de la API). */
  async sweep(): Promise<void> {
    try {
      const due = await this.reputation.call((s) => s.dueCfRules(Date.now(), 50));
      for (const key of due) await this.remove(key);
    } catch (e) {
      logger.warn(`Cloudflare sweep: ${(e as Error).message}`, 'Cloudflare');
    }
  }
}
