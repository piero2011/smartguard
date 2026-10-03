import { Controller, Get, Res, UseGuards } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { RedisService } from '../redis/redis.service';
import { ReputationService } from '../reputation/reputation.service';
import { MetricsService } from '../metrics/metrics.service';
import { ModeService } from '../scoring/mode.service';
import { ConfigService } from '../config/config.service';
import { RulesService } from '../rules/rules.service';
import { LocalOnlyGuard } from '../common/security';

/**
 * /health  liveness (el proceso responde)
 * /ready   readiness (Redis OK o circuito degradado pero funcional)
 * /metrics Prometheus (si ENABLE_PROMETHEUS=true)
 * Todo solo desde loopback.
 */
@Controller()
@UseGuards(LocalOnlyGuard)
export class HealthController {
  private readonly started = Date.now();

  constructor(
    private readonly redis: RedisService,
    private readonly reputation: ReputationService,
    private readonly metrics: MetricsService,
    private readonly mode: ModeService,
    private readonly config: ConfigService,
    private readonly rules: RulesService,
  ) {}

  @Get('health')
  async health(): Promise<Record<string, unknown>> {
    const redis = await this.redis.ping();
    return {
      status: 'ok',
      redis,
      redisCircuit: this.redis.circuitState(),
      degraded: this.reputation.degraded,
      mode: this.mode.audit ? 'AUDIT' : 'ENFORCE',
      uptime: Math.round((Date.now() - this.started) / 1000),
      rules: this.rules.info().globalRules,
    };
  }

  @Get('ready')
  async ready(@Res() reply: FastifyReply): Promise<void> {
    const redisOk = !this.config.env.redisEnabled || (await this.redis.ping());
    this.metrics.degraded.set(this.reputation.degraded ? 1 : 0);
    // Aunque Redis falle respondemos 200 con degraded=true: SmartGuard sigue decidiendo en memoria.
    reply.code(200).send({ status: redisOk ? 'ready' : 'degraded', redis: redisOk, circuit: this.redis.circuitState() });
  }

  @Get('metrics')
  async prometheus(@Res() reply: FastifyReply): Promise<void> {
    if (!this.config.env.enablePrometheus) {
      reply.code(404).send();
      return;
    }
    this.metrics.degraded.set(this.reputation.degraded ? 1 : 0);
    reply.header('content-type', this.metrics.registry.contentType).send(await this.metrics.registry.metrics());
  }
}
