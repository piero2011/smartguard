import { Confidence, EventCategory, Severity } from '../common/types';

/** Sobre qué parte de la petición se evalúa el patrón. */
export type RuleTarget = 'path' | 'query' | 'uri' | 'ua' | 'method';

/**
 * - score : suma puntos (por defecto)
 * - block : además bloquea ESTA petición inmediatamente (en ENFORCE), aunque el score no llegue al umbral.
 *           Reservado para payloads inequívocos (RCE, traversal a /etc/passwd...).
 * - allow : excepción explícita; si coincide, la petición no suma puntos por reglas (útil para falsos positivos).
 */
export type RuleAction = 'score' | 'block' | 'allow';

/** decision = en tiempo real (auth_request) · analyzer = desde el log · both = ambos (el analyzer evita duplicar). */
export type RulePhase = 'decision' | 'analyzer' | 'both';

export interface RuleDef {
  id: string;
  name: string;
  enabled?: boolean;
  target?: RuleTarget;
  pattern: string;
  /** solo se admite "i" (case-insensitive) */
  flags?: string;
  /** métodos HTTP; vacío o ["ANY"] = todos */
  methods?: string[];
  score: number;
  severity: Severity;
  confidence?: Confidence;
  category: EventCategory;
  action?: RuleAction;
  /** segundos mínimos que la reputación de la IP se conserva tras disparar esta regla */
  ttl?: number;
  /** solo para phase analyzer: estados HTTP de respuesta requeridos (p. ej. [404]) */
  status?: number[];
  phase?: RulePhase;
}

export interface CompiledRule {
  id: string;
  name: string;
  target: RuleTarget;
  regex: RegExp;
  methods: Set<string> | null;
  score: number;
  severity: Severity;
  confidence: Confidence;
  category: EventCategory;
  action: RuleAction;
  ttl: number;
  status: Set<number> | null;
  phase: RulePhase;
}

export interface RuleMatch {
  rule: CompiledRule;
}

export interface BehaviorSignal {
  score: number;
  confidence: Confidence;
  windowSec?: number;
  threshold?: number;
}

export interface BehaviorConfig {
  notFound: BehaviorSignal;
  notFoundBurst: BehaviorSignal;
  phpNotFound: BehaviorSignal;
  pluginEnum: BehaviorSignal;
  loginFailed: BehaviorSignal;
  loginStuffing: BehaviorSignal;
  rateLimited: BehaviorSignal;
  nginxDenied: BehaviorSignal;
}

export interface RulesFile {
  version: number;
  behavior: BehaviorConfig;
  rules: RuleDef[];
}

export interface SiteRulesConfig {
  disabled: string[];
  overrides: Record<string, Partial<RuleDef>>;
  extra: RuleDef[];
}

export interface SiteConfig {
  name: string;
  aliases: string[];
  wordpress: boolean;
  multisite: boolean;
  woocommerce: boolean;
  xmlrpc: boolean;
  rules: SiteRulesConfig;
}

export interface SitesFile {
  defaults: Omit<SiteConfig, 'name' | 'aliases' | 'rules'>;
  sites: SiteConfig[];
}

export interface BotDef {
  id: string;
  name: string;
  ua: string;
  /** fcrdns = DNS inverso + directo; none = no verificable (sin privilegios) */
  verify: 'fcrdns' | 'none';
  domains: string[];
}

export interface BadBotDef {
  id: string;
  ua: string;
  score: number;
  confidence: Confidence;
  category: EventCategory;
}

export interface BotsFile {
  verified: BotDef[];
  bad: BadBotDef[];
}
