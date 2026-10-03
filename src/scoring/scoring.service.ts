import { Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { RulesService, CompiledBot } from '../rules/rules.service';
import { ReputationService } from '../reputation/reputation.service';
import { ApplyResult, ScoringParams } from '../reputation/reputation.store';
import { BanService } from '../ban/ban.service';
import { AllowlistService } from '../whitelist/allowlist.service';
import { BotVerifierService } from '../bots/bot-verifier.service';
import { ModeService } from './mode.service';
import { MetricsService } from '../metrics/metrics.service';
import { StatsService } from '../stats/stats.service';
import { AllowType, Confidence, DecisionAction, EventCategory, SecurityDecision, SecurityEvent, Severity } from '../common/types';
import { ParsedIp, ipKey } from '../common/ip.util';
import { redactQuery } from '../common/uri.util';
import { logger } from '../common/logger';
import { BuiltContext, fingerprint } from './request-context';
import { RuleTarget } from '../rules/rule.types';

/** Una señal puntuable (de una regla, del comportamiento o de la verificación de bots). */
export interface Signal {
  id: string;
  score: number;
  confidence: Confidence;
  category: EventCategory;
  severity: Severity;
  /** cuenta para la detección de escaneo rápido (ventana de hits) */
  hit: boolean;
  ttl?: number;
  target?: RuleTarget;
}

export interface EvalMeta {
  source: 'decision' | 'analyzer' | 'bot-verifier';
  status?: number;
  /** alguna regla con action=block coincidió en esta petición */
  blockNow?: string | null;
}

const SEV_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Motor de scoring y decisión (puntos 9, 10, 11, 76, 82, 83).
 *
 * Reglas clave anti-falsos-positivos:
 *  1. El VOLUMEN por sí solo nunca suma puntos aquí (eso lo hace Nginx con límites altos por endpoint).
 *  2. Confianza de la señal → alcance: low = solo huella IP+UA; medium = IP + huella;
 *     high = IP + huella + "evidencia fuerte".
 *  3. Banear la IP COMPLETA exige score ≥ SCORE_BLOCK **y** evidencia fuerte ≥ STRONG_EVIDENCE_MIN.
 *     Sin evidencia fuerte, lo máximo es RATE_LIMIT (NAT corporativo protegido).
 *  4. Score decae linealmente (SCORE_DECAY_PER_MINUTE): nada queda marcado para siempre.
 *  5. Un ban nuevo solo se crea si ESTA petición aporta señales (una IP con score alto residual que
 *     navega normal queda en RESTRICTION, no se re-banea).
 *  6. Allowlist y bots verificados por FCrDNS nunca se bloquean (se registra su actividad anómala).
 */
@Injectable()
export class ScoringService implements OnModuleInit {
  constructor(
    private readonly config: ConfigService,
    private readonly rules: RulesService,
    private readonly reputation: ReputationService,
    private readonly bans: BanService,
    private readonly allowlist: AllowlistService,
    private readonly bots: BotVerifierService,
    private readonly mode: ModeService,
    private readonly metrics: MetricsService,
    private readonly stats: StatsService,
  ) {}

  onModuleInit(): void {
    this.bots.onFake = (ip, bot) => void this.applyFakeBot(ip, bot);
  }

  params(): ScoringParams {
    const e = this.config.env;
    return {
      decayPerMinute: e.decayPerMinute,
      burstWindowMs: e.burstWindowSec * 1000,
      burstThreshold: e.burstThreshold,
      burstBonus: e.burstBonus,
      reasonsMax: e.reasonsMax,
    };
  }

  /** Decisión en tiempo real para una petición que va a PHP (auth_request). */
  async decide(built: BuiltContext): Promise<SecurityDecision> {
    const { ctx, ip } = built;
    const ev = this.rules.evaluate(ctx, 'decision');
    const signals: Signal[] = ev.matches.map((r) => ({
      id: r.id,
      score: r.score,
      confidence: r.confidence,
      category: r.category,
      severity: r.severity,
      hit: true,
      ttl: r.ttl,
      target: r.target,
    }));
    if (ctx.uriFlags.nullByte) {
      signals.push({ id: 'null-byte', score: 20, confidence: 'high', category: 'TRAVERSAL', severity: 'high', hit: true });
    }

    let verifiedBot: string | null = null;
    const vb = this.rules.matchVerifiedBot(ctx.userAgent);
    if (vb) {
      const st = this.bots.status(ip, vb);
      if (st.state === 'verified') verifiedBot = st.bot;
      else if (st.state === 'fake') {
        signals.push({ id: `fake-bot:${vb.id}`, score: this.config.env.fakeBotScore, confidence: 'medium', category: 'BAD_BOT', severity: 'medium', hit: false });
      }
    } else if (ctx.userAgent) {
      const bad = this.rules.matchBadBot(ctx.userAgent);
      if (bad) signals.push({ id: `bad-bot:${bad.id}`, score: bad.score, confidence: bad.confidence, category: bad.category, severity: 'medium', hit: false });
    }

    const blockNow = ev.blockNow ? (ev.matches.find((m) => m.action === 'block')?.id ?? 'rule') : null;
    return this.evaluate(built, signals, { source: 'decision', blockNow }, verifiedBot);
  }

  /**
   * Aplica señales y devuelve la decisión. Punto común de la decisión en línea y del analizador.
   */
  async evaluate(built: BuiltContext, signals: Signal[], meta: EvalMeta, verifiedBot: string | null = null): Promise<SecurityDecision> {
    const env = this.config.env;
    const { ctx, ip, tcp, fpKey } = built;
    const audit = this.mode.audit;
    const now = Date.now();

    let ipDelta = 0;
    let fpDelta = 0;
    let strongDelta = 0;
    let hit = false;
    let ttl = env.ipTtlSec;
    for (const s of signals) {
      fpDelta += s.score;
      if (s.confidence !== 'low') ipDelta += s.score;
      if (s.confidence === 'high') strongDelta += s.score;
      // señales de baja confianza no cuentan para "escaneo rápido" (que suma evidencia fuerte a la IP)
      if (s.hit && s.confidence !== 'low') hit = true;
      if (s.ttl && s.ttl > ttl) ttl = s.ttl;
    }
    const reasons = signals.map((s) => `${s.id}+${s.score}`);

    if (meta.source === 'decision') {
      this.stats.incr('requests');
      this.stats.seenIp(ctx.ipKey);
    }

    // --- allowlist / bot verificado: nunca se bloquea, pero se registra lo anómalo ------------
    // FCrDNS de *.dominio solo se consulta si la petición ya es sospechosa (nunca para tráfico normal)
    const allowType: AllowType | null = this.allowlist.classify(ip, { lookup: signals.length > 0 }) ?? (verifiedBot ? 'VERIFIED_BOT' : null);
    const hostExempt = !allowType && this.allowlist.hostAllowed(ctx.rawHost);
    if (allowType || hostExempt) {
      const basis = hostExempt ? 'allowlist:HOST' : allowType === 'VERIFIED_BOT' ? `verified-bot:${verifiedBot}` : `allowlist:${allowType}`;
      const d = this.result('ALLOW', audit, 0, 0, 0, 0, reasons, basis);
      if (signals.length) this.record(built, signals, d, meta);
      this.count(d, meta);
      return d;
    }

    // --- Redis (o memoria si Redis cae) ----------------------------------------------------
    let res: ApplyResult;
    try {
      res = await this.reputation.call((s) =>
        s.apply(
          {
            ipKey: ctx.ipKey,
            fpKey,
            now,
            ipDelta,
            fpDelta,
            strongDelta,
            isHit: hit,
            reason: reasons.join(',').slice(0, 400),
            ipTtlSec: ttl,
            fpTtlSec: env.fpTtlSec,
            country: ctx.country ?? '',
            audit,
          },
          this.params(),
        ),
      );
    } catch (e) {
      this.metrics.failOpen.inc();
      logger.warn(`Fallo al puntuar (fail-open): ${(e as Error).message}`, 'Scoring');
      return this.result('ALLOW', audit, 0, 0, 0, 0, reasons, 'error-fail-open');
    }
    if (res.burstBonus > 0) {
      reasons.push(`rapid_scanning+${res.burstBonus}`);
      signals.push({ id: 'rapid_scanning', score: res.burstBonus, confidence: 'high', category: 'SCANNER', severity: 'high', hit: false });
    }
    if (res.decay > 0 && signals.length) reasons.push(`decay-${res.decay.toFixed(1)}`);

    const score = Math.max(res.ipScore, res.fpScore);
    const hasSignals = ipDelta > 0 || fpDelta > 0 || res.burstBonus > 0;
    let action: DecisionAction = 'ALLOW';
    let basis = 'score';
    let expiresAt: number | undefined;

    if (res.ipBanTtlMs > 0) {
      action = 'BLOCK';
      basis = 'banned';
      expiresAt = now + res.ipBanTtlMs;
    } else if (res.fpBanTtlMs > 0) {
      action = 'BLOCK';
      basis = 'banned-fp';
      expiresAt = now + res.fpBanTtlMs;
    } else if (hasSignals && res.ipScore >= env.scoreBlock && res.strongScore >= env.strongEvidenceMin) {
      const ban = await this.safeBan(built, 'ip', ctx.ipKey, res.ipScore, reasons, meta, audit, tcp && !ctx.viaCloudflare ? tcp : null);
      action = 'BLOCK';
      basis = 'threshold';
      expiresAt = ban?.expiresAt;
    } else if (hasSignals && res.fpScore >= env.scoreBlock) {
      const ban = await this.safeBan(built, 'fp', fpKey, res.fpScore, reasons, meta, audit, null);
      action = 'BLOCK';
      basis = 'threshold-fp';
      expiresAt = ban?.expiresAt;
    } else if (meta.blockNow) {
      action = 'BLOCK';
      basis = `rule:${meta.blockNow}`;
    } else if (score >= env.scoreRateLimit) {
      const restrict = score >= env.scoreRestrict;
      const key = res.ipScore >= env.scoreRateLimit ? `ip:${ctx.ipKey}` : `fp:${fpKey}`;
      const max = restrict ? env.restrictMax : env.rateLimitMax;
      let count = 0;
      if (meta.source === 'decision') {
        try {
          count = await this.reputation.call((s) => s.throttle(key, env.rateLimitWindowSec));
        } catch {
          count = 0;
        }
      }
      if (count > max) {
        action = 'RATE_LIMIT';
        basis = restrict ? 'restriction' : 'rate-limit';
      } else {
        action = 'OBSERVE';
        basis = restrict ? 'restriction-under-quota' : 'rate-limit-under-quota';
      }
    } else if (score >= env.scoreObserve) {
      action = 'OBSERVE';
    }

    const d = this.result(action, audit, score, res.ipScore, res.fpScore, res.strongScore, reasons, basis, expiresAt);
    if (signals.length || action === 'BLOCK' || action === 'RATE_LIMIT') this.record(built, signals, d, meta);
    this.count(d, meta);
    return d;
  }

  private async safeBan(
    built: BuiltContext,
    scope: 'ip' | 'fp',
    key: string,
    score: number,
    reasons: string[],
    meta: EvalMeta,
    audit: boolean,
    tcpIp: ParsedIp | null,
  ): Promise<{ expiresAt: number } | null> {
    try {
      return await this.bans.ban({
        ip: built.ip,
        ipKey: built.ctx.ipKey,
        scope,
        key,
        reason: reasons.slice(0, 6).join(','),
        reasons,
        score,
        source: meta.source === 'analyzer' ? 'ANALYZER' : 'NGINX',
        audit,
        tcpIp,
      });
    } catch (e) {
      logger.warn(`No se pudo registrar el ban de ${key}: ${(e as Error).message}`, 'Scoring');
      return null;
    }
  }

  private result(
    action: DecisionAction,
    audit: boolean,
    score: number,
    ipScore: number,
    fpScore: number,
    strongScore: number,
    reasons: string[],
    basis: string,
    expiresAt?: number,
  ): SecurityDecision {
    return { action, audit, score, ipScore, fpScore, strongScore, reasons, basis, expiresAt };
  }

  private count(d: SecurityDecision, meta: EvalMeta): void {
    if (meta.source !== 'decision') return;
    const mode = d.audit ? 'audit' : 'enforce';
    this.metrics.requests.inc({ action: d.action, mode });
    this.stats.incr(`action_${d.action.toLowerCase()}`);
    if (d.audit && (d.action === 'BLOCK' || d.action === 'RATE_LIMIT')) {
      this.metrics.wouldBlock.inc({ action: d.action });
      this.stats.incr(`would_${d.action.toLowerCase()}`);
    } else if (!d.audit && d.action === 'BLOCK') {
      this.metrics.blocked.inc({ basis: d.basis.split(':')[0]! });
      this.stats.incr('blocked_403');
    } else if (!d.audit && d.action === 'RATE_LIMIT') {
      this.metrics.rateLimited.inc();
      this.stats.incr('limited_429');
    }
  }

  private record(built: BuiltContext, signals: Signal[], d: SecurityDecision, meta: EvalMeta): void {
    const { ctx } = built;
    const top = signals.slice().sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.score - a.score)[0];
    const delta = signals.reduce((a, s) => a + s.score, 0);
    const usedQuery = signals.some((s) => s.target === 'query' || s.target === 'uri');
    const e: SecurityEvent = {
      timestamp: Date.now(),
      requestId: ctx.requestId,
      ip: ctx.ip,
      ipKey: ctx.ipKey,
      host: ctx.host,
      method: ctx.method,
      uri: ctx.path.slice(0, 300) + (usedQuery && ctx.query ? `?${redactQuery(ctx.query)}` : ''),
      status: meta.status,
      userAgent: ctx.userAgent.slice(0, 200),
      category: top?.category ?? (d.action === 'ALLOW' ? 'NORMAL' : 'UNKNOWN'),
      severity: top?.severity ?? 'low',
      scoreDelta: delta,
      reason: d.reasons.join(',') || d.basis,
      action: d.audit ? `WOULD_${d.action}` : d.action,
      source: meta.source,
      country: ctx.country,
    };
    this.stats.event(e);
    for (const s of signals) this.metrics.scores.inc({ category: s.category, source: meta.source }, s.score);
    if (delta > 0) this.stats.attack(ctx.ipKey, ctx.path.slice(0, 200), signals.map((s) => s.id), delta);

    const level = d.action === 'BLOCK' ? 'warn' : 'info';
    logger.event(level, 'Decision', {
      decision: e.action,
      basis: d.basis,
      rid: ctx.requestId,
      ip: ctx.ip,
      host: ctx.host,
      m: ctx.method,
      uri: e.uri,
      st: meta.status,
      score: Math.round(d.score * 10) / 10,
      ipScore: Math.round(d.ipScore * 10) / 10,
      fpScore: Math.round(d.fpScore * 10) / 10,
      strong: Math.round(d.strongScore * 10) / 10,
      reasons: d.reasons,
      src: meta.source,
    });
  }

  /** Señal diferida: el FCrDNS concluyó que el "Googlebot" es falso. */
  private async applyFakeBot(ip: ParsedIp, bot: CompiledBot): Promise<void> {
    const key = ipKey(ip, this.config.env.ipv6Prefix);
    const built: BuiltContext = {
      ip,
      tcp: null,
      fpKey: fingerprint(key, `fake:${bot.id}`),
      ctx: {
        requestId: 'bot-verifier',
        ip: ip.address,
        ipKey: key,
        ipVersion: ip.version,
        tcpIp: null,
        viaCloudflare: false,
        method: 'GET',
        host: '_bot-verifier',
        rawHost: '',
        site: '_unknown',
        rawUri: '/',
        path: '/',
        query: '',
        decodedQuery: '',
        userAgent: bot.name,
        acceptLanguage: '',
        uriFlags: { malformed: false, tooLong: false, dotSegments: false, nullByte: false },
      },
    };
    try {
      if (!(await this.reputation.call((s) => s.once(`fakebot:${bot.id}:${ip.address}`, this.config.env.dnsNegativeTtlSec)))) return;
      await this.evaluate(
        built,
        [{ id: `fake-bot:${bot.id}`, score: this.config.env.fakeBotScore, confidence: 'medium', category: 'BAD_BOT', severity: 'medium', hit: false }],
        { source: 'bot-verifier' },
      );
    } catch (e) {
      logger.debug(`applyFakeBot: ${(e as Error).message}`, 'Scoring');
    }
  }
}
