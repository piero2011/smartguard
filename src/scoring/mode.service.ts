import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { ReputationService } from '../reputation/reputation.service';
import { MetricsService } from '../metrics/metrics.service';
import { logger } from '../common/logger';

/**
 * AUDIT_MODE en caliente (puntos 49, 50, 99).
 * Valor inicial: AUDIT_MODE del .env. Cambio sin reiniciar: POST /admin/mode (o `smartguard audit off`),
 * que se guarda en Redis (smartguard:config:audit) para que todas las instancias lo compartan.
 * El CLI además actualiza el .env para que sobreviva a reinicios.
 */
@Injectable()
export class ModeService implements OnModuleInit, OnModuleDestroy {
  private _audit: boolean;
  private timer: NodeJS.Timeout | null = null;

  constructor(
    config: ConfigService,
    private readonly reputation: ReputationService,
    private readonly metrics: MetricsService,
  ) {
    this._audit = config.env.auditMode;
    this.metrics.auditMode.set(this._audit ? 1 : 0);
  }

  get audit(): boolean {
    return this._audit;
  }

  async onModuleInit(): Promise<void> {
    await this.sync();
    this.timer = setInterval(() => void this.sync(), 10_000);
    this.timer.unref();
    logger.log(`Modo inicial: ${this._audit ? 'AUDIT (no bloquea)' : 'ENFORCE (bloquea)'}`, 'Mode');
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async sync(): Promise<void> {
    try {
      const v = await this.reputation.call((s) => s.getAuditOverride());
      if (v !== null && v !== this._audit) {
        this._audit = v;
        this.metrics.auditMode.set(v ? 1 : 0);
        logger.warn(`Modo cambiado a ${v ? 'AUDIT' : 'ENFORCE'} (sincronizado desde Redis)`, 'Mode');
      }
    } catch {
      /* se mantiene el modo actual */
    }
  }

  async set(audit: boolean): Promise<void> {
    await this.reputation.call((s) => s.setAuditOverride(audit));
    this._audit = audit;
    this.metrics.auditMode.set(audit ? 1 : 0);
    logger.warn(`Modo cambiado a ${audit ? 'AUDIT' : 'ENFORCE'} por API administrativa`, 'Mode');
  }
}
