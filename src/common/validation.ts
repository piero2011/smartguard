import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { ParsedIp, parseIp } from './ip.util';
import { ApiError } from './api-error';

/**
 * Validación con DECORADORES de parámetro (sin clases DTO ni class-validator/class-transformer).
 *
 *   @Post('ban')
 *   ban(@ValidBody(BanBody) body: Infer<typeof BanBody>) { ... }
 *
 *   const BanBody = {
 *     ip: field.ip(),
 *     duration: field.optional(field.duration()),
 *   };
 *
 * Reglas: cuerpo/query deben ser objetos planos; los campos no declarados se RECHAZAN (400).
 * Los errores llevan code="VALIDATION" y params.field para que el dashboard los traduzca.
 */

export interface Field<T> {
  readonly optional: boolean;
  parse(value: unknown, name: string): T;
}

function fail(name: string, msg: string): never {
  throw new ApiError(400, 'VALIDATION', `${name}: ${msg}`, { field: name, reason: msg });
}

function make<T>(parse: (v: unknown, name: string) => T): Field<T> {
  return { optional: false, parse };
}

const DURATION_RE = /^\d{1,7}[smhdw]?$/;
const IP_OR_CIDR_RE = /^[0-9a-fA-F:.]{2,45}(\/\d{1,3})?$/;
/** IP, CIDR, dominio, *.dominio o URL http(s) de un sitio */
export const ALLOW_VALUE_RE = /^(?:[0-9a-fA-F:.]{2,45}(?:\/\d{1,3})?|(?:\*\.)?[A-Za-z0-9.-]{3,253}|https?:\/\/[^\s]{3,2000})$/i;

export const field = {
  string(opts: { min?: number; max?: number; pattern?: RegExp; message?: string } = {}): Field<string> {
    return make((v, n) => {
      if (typeof v !== 'string') fail(n, 'must be a string');
      const s = v.trim();
      if (opts.min !== undefined && s.length < opts.min) fail(n, `minimum ${opts.min} characters`);
      if (opts.max !== undefined && s.length > opts.max) fail(n, `maximum ${opts.max} characters`);
      if (opts.pattern && !opts.pattern.test(s)) fail(n, opts.message ?? 'invalid format');
      return s;
    });
  },
  boolean(): Field<boolean> {
    return make((v, n) => {
      if (typeof v === 'boolean') return v;
      if (v === 'true') return true;
      if (v === 'false') return false;
      return fail(n, 'must be true/false');
    });
  },
  int(opts: { min?: number; max?: number } = {}): Field<number> {
    return make((v, n) => {
      const x = typeof v === 'string' && /^-?\d{1,9}$/.test(v) ? Number(v) : v;
      if (typeof x !== 'number' || !Number.isInteger(x)) fail(n, 'must be an integer');
      if (opts.min !== undefined && x < opts.min) fail(n, `minimum ${opts.min}`);
      if (opts.max !== undefined && x > opts.max) fail(n, `maximum ${opts.max}`);
      return x;
    });
  },
  enum<T extends string>(values: readonly T[]): Field<T> {
    return make((v, n) => {
      if (typeof v !== 'string' || !(values as readonly string[]).includes(v)) fail(n, `must be one of: ${values.join(', ')}`);
      return v as T;
    });
  },
  duration(): Field<string> {
    return field.string({ max: 10, pattern: DURATION_RE, message: 'duration: 900, 15m, 1h, 2d, 1w' });
  },
  ip(): Field<string> {
    return field.string({ max: 45, pattern: /^[0-9a-fA-F:.]{2,45}$/, message: 'must be an IPv4/IPv6 address' });
  },
  ipOrCidr(): Field<string> {
    return field.string({ max: 49, pattern: IP_OR_CIDR_RE, message: 'must be an IPv4/IPv6 address or CIDR' });
  },
  /** IP, CIDR, dominio (app.ejemplo.com), subdominios (*.ejemplo.com) o URL de un sitio. */
  allowValue(): Field<string> {
    return field.string({ max: 2048, pattern: ALLOW_VALUE_RE, message: 'must be an IP, CIDR, domain, *.domain or site URL' });
  },
  optional<T>(f: Field<T>): Field<T | undefined> {
    return { optional: true, parse: f.parse };
  },
};

export type Schema = Record<string, Field<unknown>>;
export type Infer<S extends Schema> = { [K in keyof S]: S[K] extends Field<infer T> ? T : never };

export function validate<S extends Schema>(schema: S, input: unknown, where: string): Infer<S> {
  const obj = input === undefined || input === null ? {} : input;
  if (typeof obj !== 'object' || Array.isArray(obj)) {
    throw new ApiError(400, 'VALIDATION', `${where}: a JSON object was expected`, { field: where, reason: 'object' });
  }
  const src = obj as Record<string, unknown>;
  for (const k of Object.keys(src)) {
    if (!(k in schema)) throw new ApiError(400, 'VALIDATION', `${where}: field not allowed "${k}"`, { field: k, reason: 'not_allowed' });
  }
  const out: Record<string, unknown> = {};
  for (const [k, f] of Object.entries(schema)) {
    const v = src[k];
    if (v === undefined || v === null || v === '') {
      if (!f.optional) throw new ApiError(400, 'VALIDATION', `${k}: required`, { field: k, reason: 'required' });
      out[k] = undefined;
      continue;
    }
    out[k] = f.parse(v, k);
  }
  return out as Infer<S>;
}

const bodyDecorator = createParamDecorator((schema: Schema, ctx: ExecutionContext) =>
  validate(schema, ctx.switchToHttp().getRequest<FastifyRequest>().body, 'body'),
);
const queryDecorator = createParamDecorator((schema: Schema, ctx: ExecutionContext) =>
  validate(schema, ctx.switchToHttp().getRequest<FastifyRequest>().query, 'query'),
);

/** Cuerpo JSON validado contra un esquema declarativo. */
export function ValidBody<S extends Schema>(schema: S): ParameterDecorator {
  return bodyDecorator(schema);
}

/** Query string validada contra un esquema declarativo. */
export function ValidQuery<S extends Schema>(schema: S): ParameterDecorator {
  return queryDecorator(schema);
}

/** Parámetro de ruta que debe ser una IP (IPv4/IPv6). Devuelve la IP ya parseada. */
export const IpParam = createParamDecorator((name: string, ctx: ExecutionContext): ParsedIp => {
  const params = ctx.switchToHttp().getRequest<FastifyRequest>().params as Record<string, string>;
  const raw = decodeURIComponent(params[name] ?? '');
  const ip = parseIp(raw);
  if (!ip) throw new ApiError(400, 'INVALID_IP', `${name}: invalid IP address`, { field: name, value: raw.slice(0, 64) });
  return ip;
});

/** Parámetro de ruta con un valor de allowlist (IP, CIDR, dominio, *.dominio). */
export const AllowValueParam = createParamDecorator((name: string, ctx: ExecutionContext): string => {
  const params = ctx.switchToHttp().getRequest<FastifyRequest>().params as Record<string, string>;
  const raw = decodeURIComponent(params[name] ?? '').trim();
  if (!ALLOW_VALUE_RE.test(raw)) {
    throw new ApiError(400, 'INVALID_VALUE', `${name}: must be an IP, CIDR, domain or *.domain`, { field: name, value: raw.slice(0, 64) });
  }
  return raw;
});
