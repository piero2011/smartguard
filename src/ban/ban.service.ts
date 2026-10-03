import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { ReputationService } from '../reputation/reputation.service';
import { FirewallService } from '../firewall/firewall.service';
import { CloudflareService } from '../cloudflare/cloudflare.service';
import { MetricsService } from '../metrics/metrics.service';
import { AlertsService } from '../alerts/alerts.service';
import { StatsService } from '../stats/stats.service';
import { BanRecord, BanScope, BanSource } from '../common/types';
import { ParsedIp, parseIp } from '../common/ip.util';
import { formatDuration } from '../common/uri.util';
import { logger } from '../common/logger';

export interface BanRequest {
  ip: ParsedIp;
  ipKey: string;
  scope: BanScope;
  /** clave del ban: ipKey para scope=ip, hash de huella para scope=fp */
  key: string;
  reason: string;
  reasons: string[];
  score: number;
  source: BanSource;
  audit: boolean;
  /** duración forzada (ban manual); si no, escalado por reincidencia */
  durationSec?: number;
  /** IP TCP si la conexión era directa (no Cloudflare): candidata a nftables */
  tcpIp?: ParsedIp | null;
  /** para bans manuales: sincronizar también en Cloudflare aunque no sea reincidente */
  forceCloudflare?: boolean;
}

/**
 * Gestor de bans (punto 31): ban(), unban(), isBanned(), extendBan(), getBan(), incrementRecidivism().
 *
 * Duración por reincidencia (punto 10): BAN_FIRST 15m → BAN_SECOND 1h → BAN_THIRD 6h → BAN_FOURTH 24h
 * → a partir del 5º: BAN_MAX (7 d). El contador de reincidencia caduca en RECIDIVISM_TTL_SEC (14 d),
 * así una IP no queda marcada para siempre.
 *
 * Los bans de huella (IP+UA, señales de baja confianza) duran FP_BAN_SEC (10 min) y no escalan:
 * son la vía segura para NAT (no afectan al resto de usuarios de la misma IP).
 */
@Injectable()
export class BanService implements OnApplicationBootstrap {
  constructor(
    private readonly config: ConfigService,
    private readonly reputation: ReputationService,
    private readonly firewall: FirewallService,
    private readonly cloudflare: CloudflareService,
    private readonly metrics: MetricsService,
    private readonly alerts: AlertsService,
    private readonly stats: StatsService,
  ) {}

  /** Re-sincroniza nftables con los bans activos tras reinicio (la tabla se recrea vacía). */
  async onApplicationBootstrap(): Promise<void> {
    if (!this.firewall.enabled) return;
    try {
      const bans = await this.reputation.call((s) => s.listBans(false, 0, 5000));
      let n = 0;
      for (const b of bans) {
        if (!b.firewall || b.scope !== 'ip') continue;
        const ip = parseIp(b.ip);
        if (!ip) continue;
        this.firewall.ban(b.key, ip.version, Math.floor((b.expiresAt - Date.now()) / 1000));
        n++;
      }
      if (n) logger.log(`nftables re-sincronizado con ${n} bans activos`, 'Ban');
    } catch (e) {
      logger.warn(`No se pudo re-sincronizar nftables: ${(e as Error).message}`, 'Ban');
    }
  }

  durationFor(banCount: number): number {
    const { banDurations, banMax } = this.config.env;
    if (banCount <= 0) return banDurations[0]!;
    if (banCount > banDurations.length) return banMax;
    return Math.min(banDurations[banCount - 1]!, banMax);
  }

  async incrementRecidivism(ipKey: string): Promise<number> {
    return this.reputation.call((s) => s.incrRecidivism(ipKey, this.config.env.recidivismTtlSec));
  }

  async ban(req: BanRequest): Promise<BanRecord> {
    const now = Date.now();
    let banCount: number;
    let durationSec: number;
    if (req.scope === 'fp') {
      banCount = 1;
      durationSec = req.durationSec ?? this.config.env.fpBanSec;
    } else if (req.audit) {
      // En AUDIT no se incrementa la reincidencia real: se simula la siguiente.
      banCount = (await this.reputation.call((s) => s.getRecidivism(req.ipKey))) + 1;
      durationSec = req.durationSec ?? this.durationFor(banCount);
    } else {
      banCount = await this.incrementRecidivism(req.ipKey);
      durationSec = req.durationSec ?? this.durationFor(banCount);
    }

    const useFirewall = !req.audit && req.scope === 'ip' && this.firewall.eligible(req.tcpIp ?? null);
    const record: BanRecord = {
      ip: req.ip.address,
      key: req.key,
      scope: req.scope,
      reason: req.reason.slice(0, 300),
      score: Math.round(req.score * 100) / 100,
      reasons: req.reasons.slice(0, 20),
      createdAt: now,
      expiresAt: now + durationSec * 1000,
      durationSec,
      source: req.source,
      banCount,
      audit: req.audit,
      firewall: useFirewall,
    };
    await this.reputation.call((s) => s.setBan(record));
    this.metrics.bans.inc({ scope: req.scope, source: req.source, mode: req.audit ? 'audit' : 'enforce' });
    this.stats.incr(req.audit ? 'would_ban' : 'bans');

    logger.event('warn', 'Ban', {
      msg: req.audit ? 'WOULD_BAN (AUDIT, no aplicado)' : 'BAN aplicado',
      ip: req.ip.address,
      key: req.key,
      scope: req.scope,
      score: record.score,
      reasons: record.reasons,
      duration: formatDuration(durationSec),
      banCount,
      source: req.source,
      firewall: useFirewall,
    });

    if (useFirewall && req.tcpIp) {
      // La IP TCP directa ES la del atacante: se banea su clave (IPv6 → /64)
      this.firewall.ban(req.key, req.ip.version, durationSec);
    }
    if (!req.audit && req.scope === 'ip') {
      this.cloudflare.maybeBlock(req.forceCloudflare ? { ...record, banCount: Math.max(banCount, 99), score: Math.max(record.score, 1e6) } : record, req.ip);
    }
    if (req.scope === 'ip') {
      this.alerts.notify({
        title: req.audit ? 'WOULD_BAN (audit)' : 'IP baneada',
        severity: record.score >= 150 || banCount >= 3 ? 'critical' : 'high',
        ip: req.ip.address,
        message: `score=${record.score} dur=${formatDuration(durationSec)} reincidencia=${banCount} motivos=${record.reasons.join(', ')}`,
      });
    }
    return record;
  }

  async getBan(scope: BanScope, key: string, audit = false): Promise<BanRecord | null> {
    return this.reputation.call((s) => s.getBan(scope, key, audit));
  }

  async isBanned(scope: BanScope, key: string, audit = false): Promise<boolean> {
    return (await this.getBan(scope, key, audit)) !== null;
  }

  async extendBan(scope: BanScope, key: string, extraSec: number): Promise<BanRecord | null> {
    const cur = await this.getBan(scope, key);
    if (!cur) return null;
    const updated: BanRecord = { ...cur, expiresAt: cur.expiresAt + extraSec * 1000, durationSec: cur.durationSec + extraSec };
    await this.reputation.call((s) => s.setBan(updated));
    const ip = parseIp(cur.ip);
    if (updated.firewall && ip) this.firewall.ban(cur.key, ip.version, Math.floor((updated.expiresAt - Date.now()) / 1000));
    return updated;
  }

  /**
   * Desbloqueo COMPLETO de una IP:
   *  - ban de IP (real y de auditoría), elemento nftables y regla de Cloudflare;
   *  - bans de huella (IP + User-Agent) de esa IP;
   *  - reset=true (por defecto): olvida score, motivos y reincidencia, para que la IP no vuelva a
   *    quedar bloqueada con la siguiente petición por su score residual.
   */
  async unban(
    ip: ParsedIp,
    ipKey: string,
    opts: { reset?: boolean } = {},
  ): Promise<{ removed: boolean; fingerprintBans: number; cloudflare: boolean; reset: boolean }> {
    const reset = opts.reset !== false;
    const cur = await this.getBan('ip', ipKey);
    const removed = await this.reputation.call((s) => s.deleteBan('ip', ipKey));
    if (cur?.firewall || this.firewall.enabled) this.firewall.unban(ipKey, ip.version);
    const cloudflare = await this.cloudflare.remove(ipKey).catch(() => false);

    const fpKeys = new Set<string>();
    for (const audit of [false, true]) {
      const list = await this.reputation.call((s) => s.listBans(audit, 0, 5000));
      for (const b of list) if (b.scope === 'fp' && (b.ip === ip.address || b.ip === ipKey)) fpKeys.add(b.key);
    }
    for (const k of fpKeys) await this.reputation.call((s) => s.deleteBan('fp', k));
    if (reset) await this.reputation.call((s) => s.resetIp(ipKey, [...fpKeys]));

    logger.event('warn', 'Ban', { msg: 'UNBAN manual', ip: ip.address, key: ipKey, removed, fingerprintBans: fpKeys.size, cloudflare, reset });
    return { removed: removed || fpKeys.size > 0, fingerprintBans: fpKeys.size, cloudflare, reset };
  }

  async list(audit: boolean, offset = 0, limit = 100): Promise<BanRecord[]> {
    return this.reputation.call((s) => s.listBans(audit, offset, Math.min(limit, 1000)));
  }

  async count(audit: boolean): Promise<number> {
    return this.reputation.call((s) => s.countBans(audit));
  }
}
