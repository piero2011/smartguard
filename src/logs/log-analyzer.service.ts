import { Injectable, OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { RulesService } from '../rules/rules.service';
import { ScoringService, Signal } from '../scoring/scoring.service';
import { CloudflareRangesService } from '../cloudflare/cloudflare-ranges.service';
import { MetricsService } from '../metrics/metrics.service';
import { StatsService } from '../stats/stats.service';
import { BuiltContext, buildContext } from '../scoring/request-context';
import { BehaviorSignal } from '../rules/rule.types';
import { LogTailer } from './log-tailer';
import { logger } from '../common/logger';

/** Línea del log JSON de SmartGuard (nginx/smartguard/log-format.conf). */
export interface NginxLogLine {
  ts?: string;
  rid?: string;
  ip?: string;
  tcp?: string;
  m?: string;
  h?: string;
  p?: string;
  q?: boolean;
  st?: number;
  rt?: number;
  ua?: string;
  php?: string;
  sg?: string;
  nb?: string;
  lr?: string;
  lc?: string;
}

const STATIC_EXT = /\.(?:png|jpe?g|gif|svg|webp|avif|ico|bmp|ttf|otf|eot|woff2?|css|js|mjs|map|mp4|webm|mp3|ogg|wav|pdf|txt|json)$/i;
const PLUGIN_RE = /^\/(?:[\w-]+\/)?wp-content\/(?:plugins|themes)\/([^/]{1,80})\//i;
const LOGIN_RE = /(?:^|\/)wp-login\.php$/i;

/** true al alcanzar el umbral y en cada múltiplo (abuso sostenido escala: 30, 60, 90…). */
function reached(n: number, threshold: number | undefined): boolean {
  return !!threshold && threshold > 0 && n > 0 && n % threshold === 0;
}

/** Contador de ventana fija por clave, acotado en memoria. */
export class WindowCounter {
  private m = new Map<string, { start: number; n: number; set?: Set<string> }>();
  constructor(private readonly maxKeys = 100_000) {}

  /** Devuelve el recuento tras incrementar (o el tamaño del set distinto si se pasa member). */
  hit(key: string, windowMs: number, now: number, member?: string): number {
    let e = this.m.get(key);
    if (!e || now - e.start > windowMs) {
      e = { start: now, n: 0 };
      this.m.delete(key);
      this.m.set(key, e);
      if (this.m.size > this.maxKeys) {
        const oldest = this.m.keys().next().value;
        if (oldest !== undefined) this.m.delete(oldest);
      }
    }
    if (member !== undefined) {
      e.set ??= new Set();
      // 0 = miembro ya visto (no cambia el recuento de distintos)
      if (e.set.has(member) || e.set.size >= 1000) return 0;
      e.set.add(member);
      return e.set.size;
    }
    return ++e.n;
  }
}

interface Group {
  built: BuiltContext;
  signals: Signal[];
  status?: number;
}

/**
 * Analizador asíncrono del log JSON de Nginx (punto 18). Ve lo que NO pasa por auth_request:
 * peticiones cortadas por Nginx (403/404/444/429), estáticos 4xx (enumeración de plugins),
 * resultados de login (POST wp-login.php con 200 = login fallido, 302 = éxito).
 *
 * Evita doble conteo: si la línea trae "sg" (ya decidida por auth_request), no re-aplica reglas de
 * ruta; solo añade señales que dependen del estado HTTP.
 *
 * Agrupa señales por IP/huella y las aplica cada 2 s (1 llamada Redis por IP con señales).
 */
@Injectable()
export class LogAnalyzerService implements OnApplicationBootstrap, OnModuleDestroy {
  private tailer: LogTailer | null = null;
  private groups = new Map<string, Group>();
  private counters = new WindowCounter();
  private timer: NodeJS.Timeout | null = null;
  static readonly MAX_GROUPS = 5_000;

  constructor(
    private readonly config: ConfigService,
    private readonly rules: RulesService,
    private readonly scoring: ScoringService,
    private readonly cfRanges: CloudflareRangesService,
    private readonly metrics: MetricsService,
    private readonly stats: StatsService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const env = this.config.env;
    if (!env.analyzerEnabled) {
      logger.log('Analizador de logs desactivado (ANALYZER_ENABLED=false)', 'Analyzer');
      return;
    }
    this.tailer = new LogTailer(env.analyzerLogPath, env.analyzerStateFile, (lines) => this.ingest(lines));
    await this.tailer.start();
    this.timer = setInterval(() => void this.flush(), 2000);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.tailer?.stop();
    await this.flush();
  }

  ingest(lines: string[]): void {
    const now = Date.now();
    for (const line of lines) {
      let rec: NginxLogLine;
      try {
        rec = JSON.parse(line) as NginxLogLine;
      } catch {
        this.metrics.analyzerLines.inc({ result: 'invalid' });
        continue;
      }
      this.metrics.analyzerLines.inc({ result: 'ok' });
      this.processLine(rec, now);
    }
  }

  processLine(rec: NginxLogLine, now = Date.now()): void {
    const st = typeof rec.st === 'number' ? rec.st : Number(rec.st ?? 0);
    const phpHit = !!rec.php && rec.php !== '-';
    this.stats.incr('log_lines');
    if (st === 403 || st === 404 || st === 429 || st === 444) this.stats.incr(`log_${st}`);
    if (!phpHit && (st === 403 || st === 444 || st === 429 || (st === 404 && !STATIC_EXT.test(rec.p ?? '')))) {
      this.stats.incr('php_avoided');
      this.metrics.phpAvoided.inc({ by: rec.sg ? 'smartguard' : st === 429 ? 'limit_req' : 'nginx' });
    }

    const built = buildContext(
      { ip: rec.ip, tcpIp: rec.tcp, method: rec.m, uri: rec.p, host: rec.h, userAgent: rec.ua, requestId: rec.rid },
      this.config,
      (ip) => this.cfRanges.isCloudflare(ip),
    );
    if (!built) return;
    const { ctx } = built;
    const b = this.config.rules.behavior;
    const signals: Signal[] = [];
    const alreadyDecided = !!rec.sg && rec.sg !== '-';

    // 1) reglas (fase analyzer): si ya pasó por auth_request, solo las que dependen del estado
    const ev = this.rules.evaluate(ctx, 'analyzer', st);
    if (!ev.allowedBy) {
      for (const r of ev.matches) {
        if (alreadyDecided && !r.status) continue;
        signals.push({ id: r.id, score: r.score, confidence: r.confidence, category: r.category, severity: r.severity, hit: true, ttl: r.ttl, target: r.target });
      }
    }

    // 2) comportamiento
    const add = (id: string, s: BehaviorSignal, category: Signal['category'], hit = false) => {
      if (s.score > 0) signals.push({ id, score: s.score, confidence: s.confidence, category, severity: s.confidence === 'high' ? 'high' : 'medium', hit });
    };
    const isStatic = STATIC_EXT.test(ctx.path);
    if (st === 404 && !isStatic) {
      add('not_found', b.notFound, 'SCANNER');
      if (reached(this.counters.hit(`404|${ctx.ipKey}`, (b.notFoundBurst.windowSec ?? 60) * 1000, now), b.notFoundBurst.threshold)) {
        add('many_404', b.notFoundBurst, 'SCANNER');
      }
      if (/\.php$/i.test(ctx.path)) add('php_not_found', b.phpNotFound, 'SCANNER', true);
    }
    if (st === 404 || st === 403) {
      const pm = PLUGIN_RE.exec(ctx.path);
      if (pm && reached(this.counters.hit(`plug|${ctx.ipKey}`, (b.pluginEnum.windowSec ?? 120) * 1000, now, pm[1]!.toLowerCase()), b.pluginEnum.threshold)) {
        add('plugin_enumeration', b.pluginEnum, 'WP_SCAN', true);
      }
    }
    if (ctx.method === 'POST' && LOGIN_RE.test(ctx.path) && st === 200) {
      const n = this.counters.hit(`login|${ctx.ipKey}`, (b.loginStuffing.windowSec ?? 600) * 1000, now);
      const nf = this.counters.hit(`loginfp|${built.fpKey}`, (b.loginFailed.windowSec ?? 600) * 1000, now);
      if (reached(nf, b.loginFailed.threshold)) add('login_failed_burst', b.loginFailed, 'LOGIN_ABUSE');
      if (reached(n, b.loginStuffing.threshold)) add('credential_stuffing', b.loginStuffing, 'LOGIN_ABUSE', true);
    }
    if (st === 429 && (rec.lr === 'REJECTED' || rec.lc === 'REJECTED')) add('nginx_rate_limited', b.rateLimited, 'RATE_SPIKE');
    if ((st === 403 || st === 444) && !alreadyDecided && !phpHit) add('nginx_denied', b.nginxDenied, 'SCANNER');

    if (signals.length === 0) return;
    const gk = `${ctx.ipKey}|${built.fpKey}`;
    const g = this.groups.get(gk);
    if (g) {
      g.signals.push(...signals);
      g.status = st;
      g.built = built;
    } else if (this.groups.size < LogAnalyzerService.MAX_GROUPS) {
      this.groups.set(gk, { built, signals, status: st });
    } else {
      this.metrics.analyzerLines.inc({ result: 'dropped_group' });
    }
  }

  async flush(): Promise<void> {
    if (this.groups.size === 0) return;
    const groups = [...this.groups.values()];
    this.groups = new Map();
    for (const g of groups) {
      // Limitar señales repetidas por IP en un mismo lote (p. ej. 500 × not_found)
      const merged = new Map<string, Signal>();
      for (const s of g.signals) {
        const cur = merged.get(s.id);
        if (cur) cur.score = Math.min(cur.score + s.score, s.score * 10);
        else merged.set(s.id, { ...s });
      }
      try {
        await this.scoring.evaluate(g.built, [...merged.values()], { source: 'analyzer', status: g.status });
      } catch (e) {
        logger.warn(`Analyzer flush: ${(e as Error).message}`, 'Analyzer');
      }
    }
  }
}
