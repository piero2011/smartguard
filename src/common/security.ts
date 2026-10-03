import { CanActivate, ExecutionContext, HttpException, HttpStatus, Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { timingSafeEqual, createHash } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { ConfigService } from '../config/config.service';

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

/** Rechaza cualquier petición que no venga de loopback (defensa adicional a BIND_ADDRESS=127.0.0.1). */
@Injectable()
export class LocalOnlyGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<FastifyRequest>();
    if (!isLoopbackAddress(req.socket.remoteAddress)) throw new ForbiddenException('solo loopback');
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
    if (!isLoopbackAddress(remote)) throw new ForbiddenException('solo loopback');
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
