import { AllowType, BanRecord, BanScope, SecurityEvent } from '../common/types';

export interface ScoringParams {
  decayPerMinute: number;
  burstWindowMs: number;
  burstThreshold: number;
  burstBonus: number;
  reasonsMax: number;
}

export interface ApplyInput {
  ipKey: string;
  fpKey: string;
  now: number;
  ipDelta: number;
  fpDelta: number;
  strongDelta: number;
  isHit: boolean;
  /** "env-scan+25,git-scan+25" (vacío si no hay señales) */
  reason: string;
  ipTtlSec: number;
  fpTtlSec: number;
  country: string;
  audit: boolean;
}

export interface ApplyResult {
  ipBanTtlMs: number;
  fpBanTtlMs: number;
  ipScore: number;
  strongScore: number;
  fpScore: number;
  burstBonus: number;
  decay: number;
  windowHits: number;
}

export interface IpState {
  /** score almacenado SIN decay (ver updatedAt) */
  score: number;
  updatedAt?: number;
  strong: number;
  firstSeen?: number;
  lastSeen?: number;
  hits: number;
  country?: string;
  reasons: { at: number; reason: string }[];
  recidivism: number;
}

export type AllowKind = 'cidr' | 'domain' | 'wildcard';
/** client = quién hace la petición (IP/dominio del cliente) · host = sitio/subdominio destino exento */
export type AllowTarget = 'client' | 'host';

export interface AllowEntry {
  /** IP/CIDR canónico, dominio exacto (app.ejemplo.com) o subdominios (*.ejemplo.com) */
  value: string;
  kind: AllowKind;
  target: AllowTarget;
  type: AllowType;
  note: string;
  createdAt: number;
  expiresAt?: number;
}

/** Bot bloqueado a mano desde el panel/API: texto (en minúsculas) que se busca en el User-Agent. */
export interface BlockedBot {
  pattern: string;
  note: string;
  createdAt: number;
  expiresAt?: number;
}

/** Red completa (ASN) bloqueada a mano: todos los rangos que anuncia, p. ej. un proveedor de hosting. */
export interface BlockedNetwork {
  asn: number;
  org: string;
  country: string;
  /** CIDRs anunciados por la red (IPv4 e IPv6), ya validados */
  prefixes: string[];
  note: string;
  createdAt: number;
  /** última vez que se descargó la lista de rangos */
  fetchedAt: number;
}

/** Tipos de evento por los que filtra el panel. La acción llega como BLOCK o, en AUDIT, WOULD_BLOCK. */
export const EVENT_KINDS = ['all', 'log', 'suspicious', 'wouldBlock', 'blocked', 'limited', 'st403', 'st429', 'denied'] as const;
export type EventKind = (typeof EVENT_KINDS)[number];

const KIND_MATCH: Record<EventKind, (e: SecurityEvent) => boolean> = {
  all: () => true,
  log: (e) => e.source === 'analyzer',
  suspicious: (e) => (e.action ?? '').endsWith('OBSERVE'),
  wouldBlock: (e) => e.action === 'WOULD_BLOCK' || e.action === 'WOULD_RATE_LIMIT',
  blocked: (e) => e.action === 'BLOCK',
  limited: (e) => e.action === 'RATE_LIMIT',
  st403: (e) => e.status === 403,
  st429: (e) => e.status === 429,
  denied: (e) => e.source === 'analyzer' && [403, 404, 429, 444].includes(e.status ?? 0),
};

/**
 * Filtro del listado de eventos: rango por la hora del evento (ms), IP exacta (o su clave, p. ej.
 * un /64), tipo de evento y texto libre (en minúsculas) buscado en IP, ruta, motivo, host, categoría y UA.
 */
export interface EventQuery {
  from?: number;
  to?: number;
  ip?: string;
  /** sitio: cualquiera de sus dominios (host exacto de la petición) */
  hosts?: string[];
  kind?: EventKind;
  text?: string;
}

export function eventMatches(e: SecurityEvent, q: EventQuery): boolean {
  if (q.from !== undefined && e.timestamp < q.from) return false;
  if (q.to !== undefined && e.timestamp > q.to) return false;
  if (q.ip && e.ip !== q.ip && e.ipKey !== q.ip) return false;
  if (q.hosts?.length && !q.hosts.includes(e.host)) return false;
  if (q.kind && !KIND_MATCH[q.kind](e)) return false;
  if (!q.text) return true;
  return [e.ip, e.ipKey, e.uri, e.reason, e.host, e.category, e.userAgent].some((v) => String(v ?? '').toLowerCase().includes(q.text!));
}

export function eventQueryIsEmpty(q: EventQuery): boolean {
  return q.from === undefined && q.to === undefined && !q.ip && !q.hosts?.length && !q.text && (!q.kind || q.kind === 'all');
}

/** Una página de eventos. `next` es el cursor para pedir la siguiente (null = no hay más). */
export interface EventPage {
  items: SecurityEvent[];
  next: string | null;
}

/** Lo que SmartGuard ocupa en el almacén (para el panel). null = dato no disponible. */
export interface StorageInfo {
  /** eventos guardados en el historial */
  events: number;
  /** memoria del historial de eventos, lo más pesado de SmartGuard en Redis */
  eventsBytes: number | null;
  /** memoria total del servidor Redis (compartido con otros usos, p. ej. la caché de WordPress) */
  redisUsedBytes: number | null;
}

export interface StatsBucket {
  minute: number;
  fields: Record<string, number>;
}

/**
 * Almacén de reputación. Implementaciones: Redis (producción, compartido entre instancias)
 * y memoria (tests + modo degradado cuando Redis está caído).
 */
export interface ReputationStore {
  readonly kind: 'redis' | 'memory';
  apply(input: ApplyInput, params: ScoringParams): Promise<ApplyResult>;
  throttle(key: string, windowSec: number): Promise<number>;

  setBan(record: BanRecord): Promise<void>;
  getBan(scope: BanScope, key: string, audit: boolean): Promise<BanRecord | null>;
  deleteBan(scope: BanScope, key: string): Promise<boolean>;
  listBans(audit: boolean, offset: number, limit: number): Promise<BanRecord[]>;
  countBans(audit: boolean): Promise<number>;
  incrRecidivism(ipKey: string, ttlSec: number): Promise<number>;
  getRecidivism(ipKey: string): Promise<number>;
  getIpState(ipKey: string): Promise<IpState | null>;
  /** Olvida la reputación de una IP (score, motivos, reincidencia) y de las huellas indicadas. */
  resetIp(ipKey: string, fpKeys: string[]): Promise<void>;

  getDns(ip: string): Promise<string | null>;
  setDns(ip: string, value: string, ttlSec: number): Promise<void>;

  getAuditOverride(): Promise<boolean | null>;
  setAuditOverride(audit: boolean): Promise<void>;

  listAllow(): Promise<AllowEntry[]>;
  setAllow(entry: AllowEntry): Promise<void>;
  deleteAllow(value: string): Promise<boolean>;

  listBlockedBots(): Promise<BlockedBot[]>;
  setBlockedBot(entry: BlockedBot): Promise<void>;
  deleteBlockedBot(pattern: string): Promise<boolean>;

  listBlockedNetworks(): Promise<BlockedNetwork[]>;
  setBlockedNetwork(entry: BlockedNetwork): Promise<void>;
  deleteBlockedNetwork(asn: number): Promise<boolean>;

  pushEvents(events: SecurityEvent[], maxLen: number): Promise<void>;
  /** Del más reciente al más antiguo. Con `query` busca en TODO lo almacenado, no solo en lo último. */
  listEvents(limit: number, query?: EventQuery): Promise<SecurityEvent[]>;
  /**
   * Página de eventos a partir de un cursor. Con filtros recorre una cantidad ACOTADA de eventos por
   * llamada: puede devolver menos de `limit` con `next` no nulo (quedan eventos por revisar).
   */
  pageEvents(limit: number, query: EventQuery, cursor?: string): Promise<EventPage>;

  storageInfo(): Promise<StorageInfo>;

  flushStats(minute: number, fields: Record<string, number>, ips: string[], top: TopIncrements): Promise<void>;
  readStats(minutes: number[]): Promise<StatsBucket[]>;
  /** IPs distintas vistas en esos minutos; con `hosts`, solo en esos dominios (unión). */
  readActiveIps(minutes: number[], hosts?: string[]): Promise<number>;
  /** `host`: solo lo de ese sitio; sin él, la suma de todos. */
  readTop(kind: 'paths' | 'ips' | 'rules', hours: number[], limit: number, host?: string): Promise<{ member: string; score: number }[]>;

  getCfRule(ipKey: string): Promise<{ ruleId: string; expiresAt: number } | null>;
  setCfRule(ipKey: string, ruleId: string, expiresAt: number): Promise<void>;
  deleteCfRule(ipKey: string): Promise<void>;
  dueCfRules(now: number, limit: number): Promise<string[]>;
  countCfRules(): Promise<number>;
  /** dedup genérico: true si la clave no existía (SET NX EX) */
  once(key: string, ttlSec: number): Promise<boolean>;
}

export interface TopMaps {
  paths: Map<string, number>;
  ips: Map<string, number>;
  rules: Map<string, number>;
}

export interface TopIncrements extends TopMaps {
  hour: number;
  /** los mismos "top", separados por sitio (host de la petición) */
  hosts?: Map<string, TopMaps>;
  /** IPs vistas en cada sitio, para contar las IPs activas por sitio */
  hostIps?: Map<string, string[]>;
}

/** Prefijo de los contadores por sitio dentro del hash de cada minuto: "h:<host>:<campo>". */
export const HOST_FIELD_PREFIX = 'h:';

/**
 * Duración máxima de un ban (10 años). Es lo que el panel envía para un bloqueo manual
 * "hasta que se desbloquee"; la API recorta a este valor cualquier duración mayor.
 */
export const MAX_BAN_SEC = 3650 * 86_400;

export function banIndexMember(scope: BanScope, key: string): string {
  return `${scope}|${key}`;
}
