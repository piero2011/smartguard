import { Injectable } from '@nestjs/common';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from '@prometheus-io/client';

/**
 * Métricas Prometheus (punto 36). Se exponen en GET /metrics (solo loopback) si ENABLE_PROMETHEUS=true.
 */
@Injectable()
export class MetricsService {
  readonly registry = new Registry();

  readonly requests = new Counter({
    name: 'smartguard_requests_total',
    help: 'Decisiones evaluadas por SmartGuard',
    labelNames: ['action', 'mode'] as const,
    registers: [this.registry],
  });
  readonly blocked = new Counter({
    name: 'smartguard_blocked_total',
    help: 'Peticiones bloqueadas (403) por SmartGuard (ENFORCE)',
    labelNames: ['basis'] as const,
    registers: [this.registry],
  });
  readonly rateLimited = new Counter({
    name: 'smartguard_rate_limited_total',
    help: 'Peticiones limitadas por SmartGuard (ENFORCE)',
    registers: [this.registry],
  });
  readonly wouldBlock = new Counter({
    name: 'smartguard_would_block_total',
    help: 'Peticiones que se habrían bloqueado/limitado en AUDIT',
    labelNames: ['action'] as const,
    registers: [this.registry],
  });
  readonly scores = new Counter({
    name: 'smartguard_scores_total',
    help: 'Puntos de score sumados por categoría',
    labelNames: ['category', 'source'] as const,
    registers: [this.registry],
  });
  readonly bans = new Counter({
    name: 'smartguard_bans_total',
    help: 'Bans creados',
    labelNames: ['scope', 'source', 'mode'] as const,
    registers: [this.registry],
  });
  readonly redisErrors = new Counter({
    name: 'smartguard_redis_errors_total',
    help: 'Errores de Redis (incluye timeouts)',
    registers: [this.registry],
  });
  readonly failOpen = new Counter({
    name: 'smartguard_fail_open_total',
    help: 'Decisiones que terminaron en ALLOW por error interno (fail-open)',
    registers: [this.registry],
  });
  readonly decisionDuration = new Histogram({
    name: 'smartguard_decision_duration_seconds',
    help: 'Duración de /internal/decision dentro de Node',
    buckets: [0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1],
    registers: [this.registry],
  });
  readonly cloudflareBlocks = new Counter({
    name: 'smartguard_cloudflare_blocks_total',
    help: 'Reglas de bloqueo creadas en Cloudflare',
    labelNames: ['result'] as const,
    registers: [this.registry],
  });
  readonly firewallOps = new Counter({
    name: 'smartguard_firewall_ops_total',
    help: 'Operaciones nftables',
    labelNames: ['op', 'result'] as const,
    registers: [this.registry],
  });
  readonly analyzerLines = new Counter({
    name: 'smartguard_analyzer_lines_total',
    help: 'Líneas de log procesadas por el analizador',
    labelNames: ['result'] as const,
    registers: [this.registry],
  });
  readonly phpAvoided = new Counter({
    name: 'smartguard_php_avoided_total',
    help: 'Peticiones dinámicas/de ataque cortadas antes de PHP-FPM (según log)',
    labelNames: ['by'] as const,
    registers: [this.registry],
  });
  readonly degraded = new Gauge({
    name: 'smartguard_redis_degraded',
    help: '1 si se está usando el almacén en memoria por fallo de Redis',
    registers: [this.registry],
  });
  readonly auditMode = new Gauge({
    name: 'smartguard_audit_mode',
    help: '1 = AUDIT (no bloquea), 0 = ENFORCE',
    registers: [this.registry],
  });

  constructor() {
    collectDefaultMetrics({ register: this.registry, prefix: 'smartguard_process_' });
  }
}
