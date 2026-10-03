/**
 * Lectura tipada y validada de variables de entorno.
 * systemd carga /etc/smartguard/smartguard.env con EnvironmentFile= (sin dotenv).
 * En desarrollo: node --env-file=.env dist/main.js
 */

function str(name: string, def = ''): string {
  const v = process.env[name];
  return v === undefined ? def : v.trim();
}

function int(name: string, def: number, min = -Infinity, max = Infinity): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n)) throw new Error(`Variable ${name} debe ser numérica (valor: "${raw}")`);
  if (n < min || n > max) throw new Error(`Variable ${name} fuera de rango [${min}, ${max}] (valor: ${n})`);
  return n;
}

function bool(name: string, def: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return def;
  return /^(1|true|yes|on)$/i.test(raw.trim());
}

function list(name: string): string[] {
  return str(name)
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export interface EnvConfig {
  nodeEnv: string;
  port: number;
  bindAddress: string;
  allowNonLoopbackBind: boolean;
  logLevel: string;

  redisEnabled: boolean;
  redisHost: string;
  redisPort: number;
  redisDb: number;
  redisPassword: string;
  redisUsername: string;
  redisPrefix: string;
  redisCommandTimeoutMs: number;
  redisMaxMemoryMb: number;

  auditMode: boolean;

  scoreObserve: number;
  scoreRateLimit: number;
  scoreRestrict: number;
  scoreBlock: number;
  strongEvidenceMin: number;
  decayPerMinute: number;

  banDurations: number[];
  banMax: number;
  fpBanSec: number;
  recidivismTtlSec: number;

  rateLimitWindowSec: number;
  rateLimitMax: number;
  restrictMax: number;

  ipv6Prefix: number;
  ipTtlSec: number;
  fpTtlSec: number;
  burstWindowSec: number;
  burstThreshold: number;
  burstBonus: number;
  reasonsMax: number;

  adminToken: string;
  decisionSharedSecret: string;
  adminAllowlist: string[];
  serviceAllowlist: string[];
  trustedNetworks: string[];
  /**
   * Redes desde las que se aceptan la API, el panel y la decisión además de loopback. Vacío por
   * defecto. Solo para despliegues en contenedores, donde Nginx y el host llegan por la red de Docker.
   */
  localNetworks: string[];
  allowHosts: string[];
  allowDomainRefreshSec: number;

  configDir: string;
  cloudflareIpsFile: string;

  analyzerEnabled: boolean;
  analyzerLogPath: string;
  analyzerStateFile: string;

  enableNftables: boolean;
  nftBinary: string;
  enableCloudflare: boolean;
  cloudflareApiToken: string;
  cloudflareZoneId: string;
  cloudflareAccountId: string;
  cloudflareMinScore: number;
  cloudflareMinBanCount: number;
  cloudflareMaxActiveRules: number;
  cloudflareMaxPerHour: number;

  enableGeoip: boolean;
  enablePrometheus: boolean;
  enableDashboard: boolean;

  dnsTimeoutMs: number;
  dnsPositiveTtlSec: number;
  dnsNegativeTtlSec: number;
  dnsConcurrency: number;
  fakeBotScore: number;

  alertWebhookUrl: string;
  alertMinSeverity: string;
  alertMaxPerHour: number;

  eventsStreamMaxLen: number;
}

export function loadEnv(): EnvConfig {
  const banFirst = int('BAN_FIRST', 900, 60);
  const banSecond = int('BAN_SECOND', 3600, 60);
  const banThird = int('BAN_THIRD', 21600, 60);
  const banFourth = int('BAN_FOURTH', 86400, 60);
  const banMax = int('BAN_MAX', 604800, 60);

  const cfg: EnvConfig = {
    nodeEnv: str('NODE_ENV', 'production'),
    port: int('PORT', 3100, 1, 65535),
    bindAddress: str('BIND_ADDRESS', '127.0.0.1'),
    allowNonLoopbackBind: bool('ALLOW_NON_LOOPBACK_BIND', false),
    logLevel: str('LOG_LEVEL', 'info'),

    redisEnabled: bool('REDIS_ENABLED', true),
    redisHost: str('REDIS_HOST', '127.0.0.1'),
    redisPort: int('REDIS_PORT', 6379, 1, 65535),
    redisDb: int('REDIS_DB', 0, 0, 255),
    redisPassword: str('REDIS_PASSWORD'),
    redisUsername: str('REDIS_USERNAME'),
    redisPrefix: str('REDIS_PREFIX', 'smartguard:'),
    redisCommandTimeoutMs: int('REDIS_COMMAND_TIMEOUT_MS', 60, 5, 5000),
    redisMaxMemoryMb: int('REDIS_SMARTGUARD_MAX_MB', 256, 16),

    auditMode: bool('AUDIT_MODE', true),

    scoreObserve: int('SCORE_OBSERVE', 20, 1),
    scoreRateLimit: int('SCORE_RATE_LIMIT', 40, 1),
    scoreRestrict: int('SCORE_RESTRICT', 60, 1),
    scoreBlock: int('SCORE_BLOCK', 80, 1),
    strongEvidenceMin: int('STRONG_EVIDENCE_MIN', 40, 0),
    decayPerMinute: int('SCORE_DECAY_PER_MINUTE', 2, 0, 1000),

    banDurations: [banFirst, banSecond, banThird, banFourth],
    banMax,
    fpBanSec: int('FP_BAN_SEC', 600, 30),
    recidivismTtlSec: int('RECIDIVISM_TTL_SEC', 14 * 86400, 3600),

    rateLimitWindowSec: int('RATE_LIMIT_WINDOW_SEC', 60, 5, 3600),
    rateLimitMax: int('RATE_LIMIT_MAX', 60, 1),
    restrictMax: int('RESTRICT_MAX', 15, 1),

    ipv6Prefix: int('IPV6_PREFIX', 64, 32, 128),
    ipTtlSec: int('IP_TTL_SEC', 3600, 60),
    fpTtlSec: int('FP_TTL_SEC', 1800, 60),
    burstWindowSec: int('SCAN_BURST_WINDOW_SEC', 60, 5),
    burstThreshold: int('SCAN_BURST_THRESHOLD', 4, 2),
    burstBonus: int('SCAN_BURST_BONUS', 20, 0),
    reasonsMax: int('REASONS_MAX', 50, 5, 500),

    adminToken: str('ADMIN_TOKEN'),
    decisionSharedSecret: str('DECISION_SHARED_SECRET'),
    adminAllowlist: list('ADMIN_ALLOWLIST'),
    serviceAllowlist: list('SERVICE_ALLOWLIST'),
    trustedNetworks: list('TRUSTED_NETWORKS'),
    localNetworks: list('LOCAL_NETWORKS'),
    allowHosts: list('ALLOW_HOSTS'),
    allowDomainRefreshSec: int('ALLOW_DOMAIN_REFRESH_SEC', 600, 60, 86400),

    configDir: str('CONFIG_DIR', '/etc/smartguard'),
    cloudflareIpsFile: str('CLOUDFLARE_IPS_FILE', '/etc/smartguard/cloudflare-ips.txt'),

    analyzerEnabled: bool('ANALYZER_ENABLED', true),
    analyzerLogPath: str('ANALYZER_LOG_PATH', '/var/log/nginx/smartguard/access.json'),
    analyzerStateFile: str('ANALYZER_STATE_FILE', '/var/lib/smartguard/analyzer.state'),

    enableNftables: bool('ENABLE_NFTABLES', false),
    nftBinary: str('NFT_BINARY', '/usr/sbin/nft'),
    enableCloudflare: bool('ENABLE_CLOUDFLARE', false),
    cloudflareApiToken: str('CLOUDFLARE_API_TOKEN'),
    cloudflareZoneId: str('CLOUDFLARE_ZONE_ID'),
    cloudflareAccountId: str('CLOUDFLARE_ACCOUNT_ID'),
    cloudflareMinScore: int('CLOUDFLARE_MIN_SCORE', 100, 1),
    cloudflareMinBanCount: int('CLOUDFLARE_MIN_BAN_COUNT', 2, 1),
    cloudflareMaxActiveRules: int('CLOUDFLARE_MAX_ACTIVE_RULES', 200, 1, 10000),
    cloudflareMaxPerHour: int('CLOUDFLARE_MAX_PER_HOUR', 30, 1, 1000),

    enableGeoip: bool('ENABLE_GEOIP', false),
    enablePrometheus: bool('ENABLE_PROMETHEUS', true),
    enableDashboard: bool('ENABLE_DASHBOARD', true),

    dnsTimeoutMs: int('DNS_TIMEOUT_MS', 1500, 100, 10000),
    dnsPositiveTtlSec: int('DNS_POSITIVE_TTL_SEC', 86400, 60),
    dnsNegativeTtlSec: int('DNS_NEGATIVE_TTL_SEC', 21600, 60),
    dnsConcurrency: int('DNS_CONCURRENCY', 4, 1, 64),
    fakeBotScore: int('FAKE_BOT_SCORE', 15, 0),

    alertWebhookUrl: str('ALERT_WEBHOOK_URL'),
    alertMinSeverity: str('ALERT_MIN_SEVERITY', 'critical'),
    alertMaxPerHour: int('ALERT_MAX_PER_HOUR', 30, 1),

    eventsStreamMaxLen: int('EVENTS_STREAM_MAXLEN', 20000, 100, 1_000_000),
  };

  validate(cfg);
  return cfg;
}

function isLoopback(addr: string): boolean {
  return addr === '127.0.0.1' || addr === '::1' || addr === 'localhost';
}

function validate(c: EnvConfig): void {
  const errors: string[] = [];
  if (!isLoopback(c.bindAddress) && !c.allowNonLoopbackBind) {
    errors.push(`BIND_ADDRESS=${c.bindAddress} no es loopback. La API no debe exponerse (usa 127.0.0.1).`);
  }
  if (!(c.scoreObserve < c.scoreRateLimit && c.scoreRateLimit <= c.scoreRestrict && c.scoreRestrict <= c.scoreBlock)) {
    errors.push('Umbrales inválidos: se requiere SCORE_OBSERVE < SCORE_RATE_LIMIT <= SCORE_RESTRICT <= SCORE_BLOCK');
  }
  if (c.nodeEnv === 'production') {
    if (c.adminToken.length < 32) errors.push('ADMIN_TOKEN debe tener al menos 32 caracteres (openssl rand -hex 32).');
    if (c.decisionSharedSecret.length < 24) errors.push('DECISION_SHARED_SECRET debe tener al menos 24 caracteres.');
  }
  if (c.enableCloudflare && (!c.cloudflareApiToken || (!c.cloudflareZoneId && !c.cloudflareAccountId))) {
    errors.push('ENABLE_CLOUDFLARE=true requiere CLOUDFLARE_API_TOKEN y CLOUDFLARE_ACCOUNT_ID o CLOUDFLARE_ZONE_ID.');
  }
  if (errors.length) throw new Error('Configuración inválida:\n - ' + errors.join('\n - '));
}
