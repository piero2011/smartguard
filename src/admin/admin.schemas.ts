import { field } from '../common/validation';

/**
 * Esquemas declarativos de la API admin (se aplican con @ValidBody / @ValidQuery).
 * No son clases DTO: objetos planos de campos con su validador.
 */

export const BanBody = {
  ip: field.ip(),
  duration: field.optional(field.duration()),
  reason: field.optional(field.string({ max: 200 })),
  /** además en nftables (solo si la IP es de conexión directa, nunca Cloudflare) */
  firewall: field.optional(field.boolean()),
  /** además en Cloudflare (si ENABLE_CLOUDFLARE=true) */
  cloudflare: field.optional(field.boolean()),
};

export const UnbanQuery = {
  /** false = conservar score/motivos (por defecto se resetean) */
  reset: field.optional(field.boolean()),
};

export const AllowBody = {
  /** IP, CIDR, dominio exacto (app.ejemplo.com) o subdominios (*.ejemplo.com) */
  value: field.allowValue(),
  type: field.optional(field.enum(['ADMIN_ALLOWLIST', 'SERVICE_ALLOWLIST', 'TRUSTED_NETWORK'] as const)),
  /** client = quien hace la petición · host = sitio/subdominio destino exento de SmartGuard */
  target: field.optional(field.enum(['client', 'host'] as const)),
  note: field.optional(field.string({ max: 200 })),
  ttl: field.optional(field.duration()),
  /** además desbloquear la IP (si value es una IP) */
  unban: field.optional(field.boolean()),
};

export const BotBody = {
  /** texto que se busca en el User-Agent (sin distinguir mayúsculas), p. ej. "dotbot" */
  pattern: field.string({ min: 3, max: 64 }),
  note: field.optional(field.string({ max: 200 })),
  ttl: field.optional(field.duration()),
};

export const BotQuery = {
  pattern: field.string({ min: 3, max: 64 }),
};

export const NetworkBody = {
  /** IP cuya red completa se bloquea (se averigua su ASN)… */
  ip: field.optional(field.ip()),
  /** …o el número de ASN directamente */
  asn: field.optional(field.int({ min: 1, max: 4_294_967_295 })),
  note: field.optional(field.string({ max: 200 })),
};

export const NetworkQuery = {
  asn: field.int({ min: 1, max: 4_294_967_295 }),
};

export const IpInfoQuery = {
  /** hasta 50 IPs separadas por comas */
  ips: field.string({ max: 2500, pattern: /^[0-9a-fA-F:.]{2,45}(,[0-9a-fA-F:.]{2,45}){0,49}$/, message: 'up to 50 comma-separated IP addresses' }),
};

export const LookupQuery = {
  /** IP, CIDR, dominio, *.dominio o URL */
  value: field.allowValue(),
};

export const ModeBody = {
  audit: field.boolean(),
};

export const ListQuery = {
  audit: field.optional(field.boolean()),
  offset: field.optional(field.int({ min: 0, max: 1_000_000 })),
  limit: field.optional(field.int({ min: 1, max: 1000 })),
};

export const StatsQuery = {
  minutes: field.optional(field.int({ min: 1, max: 1440 })),
};
