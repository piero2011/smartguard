import { field } from '../common/validation';
import { EVENT_KINDS } from '../reputation/reputation.store';
import { EVENT_CATEGORIES } from '../common/types';

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

/** Regla creada desde el panel (mismos campos que una regla de rules.yaml). */
export const PanelRuleBody = {
  id: field.string({ min: 2, max: 64, pattern: /^[a-z0-9][a-z0-9_.-]{1,63}$/, message: 'lowercase letters, digits, "_", "." or "-" (2-64)' }),
  name: field.optional(field.string({ max: 120 })),
  enabled: field.optional(field.boolean()),
  target: field.enum(['path', 'query', 'uri', 'ua', 'method'] as const),
  pattern: field.string({ min: 1, max: 500 }),
  /** métodos HTTP separados por comas; vacío = todos */
  methods: field.optional(field.string({ max: 60, pattern: /^[A-Za-z]{3,7}(,[A-Za-z]{3,7}){0,7}$/, message: 'comma-separated HTTP methods' })),
  score: field.int({ min: 0, max: 1000 }),
  severity: field.enum(['low', 'medium', 'high', 'critical'] as const),
  confidence: field.optional(field.enum(['low', 'medium', 'high'] as const)),
  category: field.enum(EVENT_CATEGORIES),
  action: field.optional(field.enum(['score', 'block', 'allow'] as const)),
};

export const PanelRuleQuery = {
  id: PanelRuleBody.id,
};

export const ModeBody = {
  audit: field.boolean(),
};

export const ListQuery = {
  audit: field.optional(field.boolean()),
  offset: field.optional(field.int({ min: 0, max: 1_000_000 })),
  limit: field.optional(field.int({ min: 1, max: 1000 })),
};

export const EventsQuery = {
  limit: field.optional(field.int({ min: 1, max: 1000 })),
  /** rango por la hora del evento, en milisegundos desde epoch */
  from: field.optional(field.string({ pattern: /^\d{1,14}$/, message: 'must be a timestamp in milliseconds' })),
  to: field.optional(field.string({ pattern: /^\d{1,14}$/, message: 'must be a timestamp in milliseconds' })),
  /** IP exacta o clave de reputación (un /64 de IPv6) */
  ip: field.optional(field.ipOrCidr()),
};

/** Página de eventos del panel (cursor en lugar de offset: el stream crece por delante mientras se pagina). */
export const EventsPageQuery = {
  limit: field.optional(field.int({ min: 1, max: 200 })),
  cursor: field.optional(field.string({ pattern: /^\d{1,15}-\d{1,20}$/, message: 'invalid cursor' })),
  from: EventsQuery.from,
  to: EventsQuery.to,
  kind: field.optional(field.enum(EVENT_KINDS)),
  host: field.optional(field.string({ max: 100, pattern: /^[a-z0-9_]([a-z0-9._-]{0,98}[a-z0-9])?$/, message: 'must be a host name' })),
  /** texto libre: IP, ruta, motivo, host, categoría o User-Agent */
  q: field.optional(field.string({ max: 100 })),
};

/** Host de un sitio protegido (dominio en minúsculas) */
const hostField = () => field.optional(field.string({ max: 100, pattern: /^[a-z0-9]([a-z0-9.-]{0,98}[a-z0-9])?$/, message: 'must be a host name' }));

export const StatsQuery = {
  minutes: field.optional(field.int({ min: 1, max: 1440 })),
  /** solo las cifras de este sitio; sin él, la suma de todos */
  host: hostField(),
};
