import { Injectable, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { ConfigService } from '../config/config.service';
import { logger } from '../common/logger';
import { DECIDE_LUA, THROTTLE_LUA } from './lua';

export type RedisWithScripts = Redis & {
  sgDecide(...args: (string | number)[]): Promise<number[]>;
  sgThrottle(key: string, ttl: number): Promise<number>;
};

/**
 * Conexión Redis + circuit breaker (puntos 8, 73).
 *
 * - enableOfflineQueue=false: si Redis está caído los comandos fallan AL INSTANTE (no se encolan),
 *   así una decisión nunca espera a Redis → fail-open inmediato.
 * - commandTimeout corto (60 ms por defecto).
 * - retryStrategy con backoff exponencial hasta 30 s: sin tormenta de reconexiones.
 * - Circuit breaker: 5 errores en 10 s → circuito ABIERTO 30 s (se usa el almacén en memoria local).
 */
@Injectable()
export class RedisService implements OnModuleDestroy {
  readonly client: RedisWithScripts | null;
  private failures: number[] = [];
  private openUntil = 0;
  private halfOpenProbe = false;
  errorCount = 0;
  onError: (() => void) | null = null;

  static readonly FAILURE_THRESHOLD = 5;
  static readonly FAILURE_WINDOW_MS = 10_000;
  static readonly OPEN_MS = 30_000;

  constructor(private readonly config: ConfigService) {
    const env = config.env;
    if (!env.redisEnabled) {
      this.client = null;
      return;
    }
    const client = new Redis({
      host: env.redisHost,
      port: env.redisPort,
      db: env.redisDb,
      username: env.redisUsername || undefined,
      password: env.redisPassword || undefined,
      lazyConnect: false,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 0,
      commandTimeout: env.redisCommandTimeoutMs,
      connectTimeout: 2000,
      enableReadyCheck: true,
      connectionName: 'smartguard',
      retryStrategy: (times: number) => Math.min(30_000, 250 * 2 ** Math.min(times, 7)),
      reconnectOnError: () => false,
    }) as RedisWithScripts;
    client.defineCommand('sgDecide', { numberOfKeys: 6, lua: DECIDE_LUA });
    client.defineCommand('sgThrottle', { numberOfKeys: 1, lua: THROTTLE_LUA });
    let lastLog = 0;
    client.on('error', (err: Error) => {
      const now = Date.now();
      if (now - lastLog > 30_000) {
        lastLog = now;
        logger.warn(`Redis error: ${err.message}`, 'Redis');
      }
    });
    client.on('ready', () => logger.log('Redis conectado', 'Redis'));
    this.client = client;
  }

  key(suffix: string): string {
    return this.config.env.redisPrefix + suffix;
  }

  /** true si se puede intentar usar Redis ahora mismo. */
  available(): boolean {
    if (!this.client) return false;
    if (this.client.status !== 'ready') return false;
    const now = Date.now();
    if (now < this.openUntil) return false;
    if (this.openUntil > 0 && !this.halfOpenProbe) {
      // medio abierto: dejar pasar una prueba
      this.halfOpenProbe = true;
    }
    return true;
  }

  circuitState(): 'closed' | 'open' | 'half-open' | 'disabled' {
    if (!this.client) return 'disabled';
    const now = Date.now();
    if (now < this.openUntil) return 'open';
    return this.openUntil > 0 ? 'half-open' : 'closed';
  }

  recordSuccess(): void {
    if (this.openUntil > 0) {
      this.openUntil = 0;
      this.halfOpenProbe = false;
      this.failures = [];
      logger.log('Circuit breaker Redis CERRADO (recuperado)', 'Redis');
    }
  }

  recordFailure(err: unknown): void {
    this.errorCount++;
    this.onError?.();
    const now = Date.now();
    if (this.openUntil > 0 && this.halfOpenProbe) {
      this.openUntil = now + RedisService.OPEN_MS;
      this.halfOpenProbe = false;
      return;
    }
    this.failures = this.failures.filter((t) => now - t < RedisService.FAILURE_WINDOW_MS);
    this.failures.push(now);
    if (this.failures.length >= RedisService.FAILURE_THRESHOLD) {
      this.openUntil = now + RedisService.OPEN_MS;
      this.failures = [];
      logger.warn(`Circuit breaker Redis ABIERTO ${RedisService.OPEN_MS / 1000}s: ${(err as Error)?.message ?? err}`, 'Redis');
    }
  }

  /** Ejecuta fn contra Redis con registro en el circuit breaker. Lanza si no está disponible. */
  async run<T>(fn: (c: RedisWithScripts) => Promise<T>): Promise<T> {
    if (!this.available()) throw new Error('redis-unavailable');
    try {
      const r = await fn(this.client!);
      this.recordSuccess();
      return r;
    } catch (e) {
      this.recordFailure(e);
      throw e;
    }
  }

  async ping(): Promise<boolean> {
    if (!this.client || this.client.status !== 'ready') return false;
    try {
      return (await this.client.ping()) === 'PONG';
    } catch {
      return false;
    }
  }

  async usedMemoryMb(): Promise<number | null> {
    try {
      const info = await this.run((c) => c.info('memory'));
      const m = /used_memory:(\d+)/.exec(info);
      return m ? Number(m[1]) / 1024 / 1024 : null;
    } catch {
      return null;
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.client) {
      try {
        await this.client.quit();
      } catch {
        this.client.disconnect();
      }
    }
  }
}
