import { CanActivate, ExecutionContext, HttpException, HttpStatus, Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { timingSafeEqual, createHash } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { ConfigService } from '../config/config.service';
import { CidrSet, parseIp } from './ip.util';

export function isLoopbackAddress(addr: string | undefined): boolean {
  if (!addr) return false;
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1' || addr.startsWith('127.');
}

/** Comparación en tiempo constante (hash previo para igualar longitudes). */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb) && a.length === b.length;
}

const localSets = new WeakMap<object, CidrSet>();

/**
 * ¿La conexión es local? Loopback siempre; además, las redes de LOCAL_NETWORKS (vacío por defecto).
 * En un despliegue con Docker, Nginx y el puerto publicado en el host llegan desde la red interna de
 * los contenedores, no desde 127.0.0.1: esa red se declara ahí. Nunca debe incluir redes públicas.
 */
export function isLocalAddress(addr: string | undefined, config: ConfigService): boolean {
  if (isLoopbackAddress(addr)) return true;
  const nets = config.env.localNetworks;
  if (!addr || !nets || nets.length === 0) return false;
  let set = localSets.get(nets);
  if (!set) localSets.set(nets, (set = new CidrSet(nets)));
  return set.contains(parseIp(addr));
}

/** Rechaza cualquier petición que no sea local (defensa adicional a BIND_ADDRESS=127.0.0.1). */
@Injectable()
export class LocalOnlyGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<FastifyRequest>();
    if (!isLocalAddress(req.socket.remoteAddress, this.config)) throw new ForbiddenException('solo loopback');
    return true;
  }
}

/** Rate limit simple en memoria para la API administrativa (punto 64). */
class FixedWindowLimiter {
  private hits = new Map<string, { n: number; reset: number }>();
  constructor(private readonly max: number, private readonly windowMs: number) {}
  allow(key: string): boolean {
    const now = Date.now();
    const cur = this.hits.get(key);
    if (!cur || cur.reset <= now) {
      if (this.hits.size > 1000) this.hits.clear();
      this.hits.set(key, { n: 1, reset: now + this.windowMs });
      return true;
    }
    cur.n++;
    return cur.n <= this.max;
  }
}

/**
 * Autenticación de la API admin: loopback + "Authorization: Bearer <ADMIN_TOKEN>" (≥32 chars),
 * comparación en tiempo constante y rate limit (120 req/min; 10 fallos/min).
 */
@Injectable()
export class AdminAuthGuard implements CanActivate {
  private limiter = new FixedWindowLimiter(120, 60_000);
  private failLimiter = new FixedWindowLimiter(10, 60_000);

  constructor(private readonly config: ConfigService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<FastifyRequest>();
    const remote = req.socket.remoteAddress ?? '?';
    if (!isLocalAddress(remote, this.config)) throw new ForbiddenException('solo loopback');
    if (!this.limiter.allow(remote)) throw new HttpException('demasiadas peticiones', HttpStatus.TOO_MANY_REQUESTS);
    const token = this.config.env.adminToken;
    if (!token) throw new ForbiddenException('ADMIN_TOKEN no configurado');
    const header = req.headers.authorization ?? '';
    const given = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    if (!given || !safeEqual(given, token)) {
      if (!this.failLimiter.allow(remote)) throw new HttpException('demasiados intentos', HttpStatus.TOO_MANY_REQUESTS);
      throw new UnauthorizedException();
    }
    return true;
  }
}
