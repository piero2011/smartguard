import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { ConfigService } from '../config/config.service';
import { ScoringService } from '../scoring/scoring.service';
import { CloudflareRangesService } from '../cloudflare/cloudflare-ranges.service';
import { MetricsService } from '../metrics/metrics.service';
import { LocalOnlyGuard, safeEqual } from '../common/security';
import { buildContext } from '../scoring/request-context';
import { logger } from '../common/logger';

function h(req: FastifyRequest, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * GET /internal/decision — llamado por Nginx vía auth_request SOLO para tráfico que va a PHP-FPM.
 *
 * Cabeceras (las pone Nginx; ver nginx/smartguard/auth.conf):
 *   X-SmartGuard-Key  secreto compartido (evita que PHP/SSRF local envenene la reputación)
 *   X-Real-IP         $remote_addr (IP real ya resuelta por realip/Cloudflare)
 *   X-TCP-IP          $realip_remote_addr (IP TCP)
 *   X-Original-URI    $request_uri · X-Original-Method · X-User-Agent · X-Host · X-Request-ID
 *   X-Accept-Language · X-Country ($http_cf_ipcountry, solo se usa si TCP ∈ Cloudflare)
 *
 * Respuesta (cuerpo vacío):
 *   200 = permitir (ALLOW / OBSERVE / cualquier cosa en AUDIT)   ← también en error: FAIL-OPEN
 *   403 = bloquear · 429 = limitar (Nginx lo traduce a 403 en auth_request; ver auth.conf)
 *   X-SmartGuard-Decision: ALLOW | OBSERVE | RATE_LIMIT | BLOCK | WOULD_BLOCK | WOULD_RATE_LIMIT ...
 *
 * Camino rápido: sin I/O salvo 1 EVALSHA en Redis. Sin DNS, sin SQL, sin Cloudflare síncrono.
 */
@Controller()
@UseGuards(LocalOnlyGuard)
export class DecisionController {
  private lastAuthWarn = 0;

  constructor(
    private readonly config: ConfigService,
    private readonly scoring: ScoringService,
    private readonly cfRanges: CloudflareRangesService,
    private readonly metrics: MetricsService,
  ) {}

  @Get('internal/decision')
  async decision(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const end = this.metrics.decisionDuration.startTimer();
    try {
      const secret = this.config.env.decisionSharedSecret;
      if (secret && !safeEqual(h(req, 'x-smartguard-key') ?? '', secret)) {
        // Llamada no autorizada: no se evalúa ni se puntúa. 200 para no romper nada si Nginx se configuró mal.
        const now = Date.now();
        if (now - this.lastAuthWarn > 60_000) {
          this.lastAuthWarn = now;
          logger.warn('Llamada a /internal/decision sin X-SmartGuard-Key válido (¿secret.conf de Nginx desactualizado?)', 'Decision');
        }
        reply.code(200).header('x-smartguard-decision', 'UNAUTHENTICATED').send();
        return;
      }
      const built = buildContext(
        {
          ip: h(req, 'x-real-ip'),
          tcpIp: h(req, 'x-tcp-ip'),
          method: h(req, 'x-original-method'),
          uri: h(req, 'x-original-uri'),
          host: h(req, 'x-host'),
          userAgent: h(req, 'x-user-agent'),
          acceptLanguage: h(req, 'x-accept-language'),
          requestId: h(req, 'x-request-id'),
          country: h(req, 'x-country'),
        },
        this.config,
        (ip) => this.cfRanges.isCloudflare(ip),
      );
      if (!built) {
        reply.code(200).header('x-smartguard-decision', 'NO_IP').send();
        return;
      }
      const d = await this.scoring.decide(built);
      const label = d.audit && d.action !== 'ALLOW' ? `WOULD_${d.action}` : d.action;
      let status = 200;
      if (!d.audit) {
        if (d.action === 'BLOCK') status = 403;
        else if (d.action === 'RATE_LIMIT') status = 429;
      }
      reply
        .code(status)
        .header('x-smartguard-decision', label)
        .header('x-smartguard-score', Math.round(d.score).toString())
        .header('cache-control', 'no-store')
        .send();
    } catch (e) {
      // FAIL-OPEN: cualquier error interno permite la petición.
      this.metrics.failOpen.inc();
      logger.error(`Error en decisión (fail-open): ${(e as Error).message}`, 'Decision');
      if (!reply.sent) reply.code(200).header('x-smartguard-decision', 'ERROR_FAIL_OPEN').send();
    } finally {
      end();
    }
  }
}
