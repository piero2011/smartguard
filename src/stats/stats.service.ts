import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { ReputationService } from '../reputation/reputation.service';
import { SecurityEvent } from '../common/types';
import { logger } from '../common/logger';

/**
 * Contadores agregados EN MEMORIA y volcados a Redis cada 10 s en un único pipeline
 * (punto 94: minimizar operaciones Redis). También bufferiza los eventos de seguridad
 * hacia el stream smartguard:events.
 */
@Injectable()
export class StatsService implements OnModuleInit, OnModuleDestroy {
  private fields: Record<string, number> = {};
  private ips = new Set<string>();
  private topPaths = new Map<string, number>();
  private topIps = new Map<string, number>();
  private topRules = new Map<string, number>();
  private events: SecurityEvent[] = [];
  private minute = currentMinute();
  private timer: NodeJS.Timeout | null = null;
  static readonly MAX_IPS_BUFFER = 20_000;
  static readonly MAX_EVENTS_BUFFER = 5_000;
  static readonly MAX_TOP_BUFFER = 5_000;

  constructor(
    private readonly config: ConfigService,
    private readonly reputation: ReputationService,
  ) {}

  onModuleInit(): void {
    this.timer = setInterval(() => void this.flush(), 10_000);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.flush();
  }

  incr(field: string, by = 1): void {
    this.rollIfNeeded();
    this.fields[field] = (this.fields[field] ?? 0) + by;
  }

  seenIp(ipKey: string): void {
    if (this.ips.size < StatsService.MAX_IPS_BUFFER) this.ips.add(ipKey);
  }

  attack(ipKey: string, path: string, ruleIds: string[], points: number): void {
    bump(this.topIps, ipKey, points);
    bump(this.topPaths, path, 1);
    for (const r of ruleIds) bump(this.topRules, r, 1);
  }

  event(e: SecurityEvent): void {
    if (this.events.length < StatsService.MAX_EVENTS_BUFFER) this.events.push(e);
  }

  private rollIfNeeded(): void {
    const m = currentMinute();
    if (m !== this.minute) void this.flush();
  }

  async flush(): Promise<void> {
    const minute = this.minute;
    const fields = this.fields;
    const ips = [...this.ips];
    const top = { hour: Math.floor((minute * 60) / 3600), paths: this.topPaths, ips: this.topIps, rules: this.topRules };
    const events = this.events;
    this.minute = currentMinute();
    this.fields = {};
    this.ips = new Set();
    this.topPaths = new Map();
    this.topIps = new Map();
    this.topRules = new Map();
    this.events = [];
    try {
      if (Object.keys(fields).length || ips.length || top.paths.size) {
        await this.reputation.call((s) => s.flushStats(minute, fields, ips, top));
      }
      if (events.length) await this.reputation.call((s) => s.pushEvents(events, this.config.env.eventsStreamMaxLen));
    } catch (e) {
      logger.warn(`No se pudieron volcar estadísticas: ${(e as Error).message}`, 'Stats');
    }
  }
}

function bump(m: Map<string, number>, k: string, by: number): void {
  if (m.size >= StatsService.MAX_TOP_BUFFER && !m.has(k)) return;
  m.set(k, (m.get(k) ?? 0) + by);
}

export function currentMinute(now = Date.now()): number {
  return Math.floor(now / 60_000);
}
