import { DynamicModule, Module } from '@nestjs/common';
import { ConfigService } from './config/config.service';
import { RulesService } from './rules/rules.service';
import { RedisService } from './redis/redis.service';
import { ReputationService } from './reputation/reputation.service';
import { AllowlistService } from './whitelist/allowlist.service';
import { CloudflareRangesService } from './cloudflare/cloudflare-ranges.service';
import { CloudflareService } from './cloudflare/cloudflare.service';
import { BotVerifierService } from './bots/bot-verifier.service';
import { MetricsService } from './metrics/metrics.service';
import { AlertsService } from './alerts/alerts.service';
import { StatsService } from './stats/stats.service';
import { ModeService } from './scoring/mode.service';
import { FirewallService } from './firewall/firewall.service';
import { BanService } from './ban/ban.service';
import { ScoringService } from './scoring/scoring.service';
import { LogAnalyzerService } from './logs/log-analyzer.service';
import { DecisionController } from './nginx/decision.controller';
import { HealthController } from './health/health.controller';
import { AdminController } from './admin/admin.controller';
import { DashboardController } from './dashboard/dashboard.controller';
import { AdminAuthGuard, LocalOnlyGuard } from './common/security';

/**
 * Un único módulo: SmartGuard es un servicio pequeño y todas las piezas comparten estado
 * (config, reglas, Redis). Las carpetas separan responsabilidades; los módulos Nest adicionales
 * solo añadirían boilerplate.
 */
@Module({})
export class AppModule {
  static forRoot(opts: { config?: ConfigService } = {}): DynamicModule {
    return {
      module: AppModule,
      controllers: [DecisionController, HealthController, AdminController, DashboardController],
      providers: [
        {
          provide: ConfigService,
          useFactory: async () => {
            if (opts.config) return opts.config;
            const c = new ConfigService();
            await c.loadFiles();
            return c;
          },
        },
        {
          provide: RulesService,
          inject: [ConfigService],
          useFactory: (config: ConfigService) => {
            const r = new RulesService(config);
            r.compile();
            return r;
          },
        },
        RedisService,
        ReputationService,
        MetricsService,
        AlertsService,
        StatsService,
        ModeService,
        CloudflareRangesService,
        CloudflareService,
        FirewallService,
        AllowlistService,
        BotVerifierService,
        BanService,
        ScoringService,
        LogAnalyzerService,
        LocalOnlyGuard,
        AdminAuthGuard,
      ],
    };
  }
}
