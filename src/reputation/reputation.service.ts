import { Injectable } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import { MemoryReputationStore } from './memory.store';
import { RedisReputationStore } from './redis.store';
import { ReputationStore } from './reputation.store';

/**
 * Fachada resiliente: usa Redis cuando está disponible y, si no (caído o circuito abierto),
 * el almacén en memoria local. Así una caída de Redis nunca tira WooCommerce (punto 52 "Redis caído"):
 * la decisión sigue funcionando con reglas + estado local, y Nginx además hace fail-open.
 */
@Injectable()
export class ReputationService {
  readonly memory: MemoryReputationStore;
  private readonly redisStore: RedisReputationStore | null;
  degradedCalls = 0;

  constructor(private readonly redis: RedisService) {
    this.memory = new MemoryReputationStore();
    this.redisStore = redis.client ? new RedisReputationStore(redis) : null;
  }

  /** Almacén preferido ahora mismo. */
  get store(): ReputationStore {
    return this.redisStore && this.redis.available() ? this.redisStore : this.memory;
  }

  get degraded(): boolean {
    return this.store.kind === 'memory' && this.redisStore !== null;
  }

  /** Ejecuta en Redis y, si falla, en memoria. */
  async call<T>(fn: (s: ReputationStore) => Promise<T>): Promise<T> {
    const s = this.store;
    if (s.kind === 'memory') {
      if (this.redisStore) this.degradedCalls++;
      return fn(s);
    }
    try {
      return await fn(s);
    } catch {
      this.degradedCalls++;
      return fn(this.memory);
    }
  }
}
