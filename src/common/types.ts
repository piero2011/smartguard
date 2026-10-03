/**
 * Tipos de dominio compartidos por todo SmartGuard.
 */

export type DecisionAction = 'ALLOW' | 'OBSERVE' | 'RATE_LIMIT' | 'BLOCK';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Confianza de una señal. Determina el ALCANCE del castigo (punto 11: NAT):
 *  - low    → solo huella (IP + User-Agent + Accept-Language)
 *  - medium → huella + score de la IP (puede limitar, nunca banear la IP sola)
 *  - high   → huella + score de la IP + "evidencia fuerte" (necesaria para banear la IP)
 */
export type Confidence = 'low' | 'medium' | 'high';

export const EVENT_CATEGORIES = [
  'NORMAL',
  'RATE_SPIKE',
  'SCANNER',
  'SENSITIVE_FILE',
  'WP_SCAN',
  'LOGIN_ABUSE',
  'XMLRPC_ABUSE',
  'SQLI',
  'XSS',
  'TRAVERSAL',
  'RCE',
  'WEBSHELL_SCAN',
  'BAD_BOT',
  'VERIFIED_BOT',
  'UNKNOWN',
] as const;
export type EventCategory = (typeof EVENT_CATEGORIES)[number];

export type BanSource = 'NGINX' | 'ANALYZER' | 'MANUAL' | 'CLOUDFLARE';
export type BanScope = 'ip' | 'fp';

export interface ScoreReason {
  /** id de regla o de señal de comportamiento, p. ej. "env-scan" o "rapid_scanning" */
  id: string;
  delta: number;
  category: EventCategory;
}

export interface SecurityDecision {
  action: DecisionAction;
  /** true si estamos en AUDIT y la acción NO se aplicó realmente */
  audit: boolean;
  score: number;
  ipScore: number;
  fpScore: number;
  strongScore: number;
  reasons: string[];
  expiresAt?: number;
  /** motivo corto para cabecera/log: banned, rule:env-scan, threshold, allowlist... */
  basis: string;
}

export interface SecurityEvent {
  timestamp: number;
  requestId?: string;
  ip: string;
  ipKey: string;
  host: string;
  method: string;
  /** ruta SIN query string, truncada. La query solo se guarda redactada si una regla la usó. */
  uri: string;
  status?: number;
  userAgent: string;
  category: EventCategory;
  severity: Severity;
  scoreDelta: number;
  reason: string;
  action?: DecisionAction | `WOULD_${DecisionAction}`;
  source: 'decision' | 'analyzer' | 'admin' | 'bot-verifier';
  country?: string;
}

export interface BanRecord {
  ip: string;
  key: string;
  scope: BanScope;
  reason: string;
  score: number;
  reasons: string[];
  createdAt: number;
  expiresAt: number;
  durationSec: number;
  source: BanSource;
  banCount: number;
  audit: boolean;
  firewall: boolean;
  cloudflareRuleId?: string;
}

export type AllowType = 'ADMIN_ALLOWLIST' | 'SERVICE_ALLOWLIST' | 'TRUSTED_NETWORK' | 'VERIFIED_BOT';

/** Contexto normalizado de una petición (lo que llega de Nginx o del log). */
export interface RequestContext {
  requestId: string;
  ip: string;
  ipKey: string;
  ipVersion: 4 | 6;
  /** IP TCP real ($realip_remote_addr). Distinta de ip cuando la petición vino por Cloudflare. */
  tcpIp: string | null;
  viaCloudflare: boolean;
  method: string;
  /** host validado de un sitio configurado, o "_unknown" */
  host: string;
  /** host normalizado tal cual llegó (para exenciones ALLOW_HOSTS); nunca se usa como clave */
  rawHost: string;
  site: string;
  rawUri: string;
  path: string;
  query: string;
  decodedQuery: string;
  userAgent: string;
  acceptLanguage: string;
  country?: string;
  uriFlags: {
    malformed: boolean;
    tooLong: boolean;
    dotSegments: boolean;
    nullByte: boolean;
  };
}
