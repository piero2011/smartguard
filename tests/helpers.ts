import * as path from 'node:path';
import { EnvConfig, loadEnv } from '../src/config/env';
import { ConfigService } from '../src/config/config.service';
import { RulesService } from '../src/rules/rules.service';
import { RedisService } from '../src/redis/redis.service';
import { ReputationService } from '../src/reputation/reputation.service';
import { MetricsService } from '../src/metrics/metrics.service';
import { AlertsService } from '../src/alerts/alerts.service';
import { StatsService } from '../src/stats/stats.service';
import { ModeService } from '../src/scoring/mode.service';
import { CloudflareRangesService } from '../src/cloudflare/cloudflare-ranges.service';
import { CloudflareService } from '../src/cloudflare/cloudflare.service';
import { FirewallService } from '../src/firewall/firewall.service';
import { AllowlistService } from '../src/whitelist/allowlist.service';
import { BotVerifierService, DnsResolver } from '../src/bots/bot-verifier.service';
import { BanService } from '../src/ban/ban.service';
import { ScoringService } from '../src/scoring/scoring.service';
import { LogAnalyzerService } from '../src/logs/log-analyzer.service';
import { BuiltContext, RawRequest, buildContext } from '../src/scoring/request-context';

export const CONFIG_DIR = path.join(__dirname, '..', 'config');

/** Construye EnvConfig a partir de variables (sin tocar el process.env global de forma permanente). */
export function testEnv(vars: Record<string, string> = {}): EnvConfig {
  const base: Record<string, string> = {
    NODE_ENV: 'test',
    REDIS_ENABLED: 'false',
    AUDIT_MODE: 'false',
    CONFIG_DIR,
    CLOUDFLARE_IPS_FILE: path.join(__dirname, 'no-such-file.txt'),
    ANALYZER_ENABLED: 'false',
    ADMIN_TOKEN: 'test-admin-token-0123456789abcdef0123456789',
    DECISION_SHARED_SECRET: 'test-decision-secret-0123456789',
    ...vars,
  };
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(base)) {
    saved[k] = process.env[k];
    process.env[k] = v;
  }
  try {
    return loadEnv();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

export class FakeResolver implements DnsResolver {
  ptr = new Map<string, string[]>();
  a = new Map<string, string[]>();
  aaaa = new Map<string, string[]>();
  async reverse(ip: string): Promise<string[]> {
    const v = this.ptr.get(ip);
    if (!v) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return v;
  }
  async resolve4(h: string): Promise<string[]> {
    return this.a.get(h) ?? [];
  }
  async resolve6(h: string): Promise<string[]> {
    return this.aaaa.get(h) ?? [];
  }
}

export interface Harness {
  config: ConfigService;
  rules: RulesService;
  redis: RedisService;
  reputation: ReputationService;
  metrics: MetricsService;
  stats: StatsService;
  mode: ModeService;
  cfRanges: CloudflareRangesService;
  allowlist: AllowlistService;
  bots: BotVerifierService;
  resolver: FakeResolver;
  bans: BanService;
  scoring: ScoringService;
  analyzer: LogAnalyzerService;
  req(r: Partial<RawRequest> & { ip: string }): BuiltContext;
}

export async function makeHarness(vars: Record<string, string> = {}): Promise<Harness> {
  const env = testEnv(vars);
  const config = new ConfigService(env);
  await config.loadFiles();
  const rules = new RulesService(config);
  rules.compile();
  const redis = new RedisService(config);
  const reputation = new ReputationService(redis);
  const metrics = new MetricsService();
  const alerts = new AlertsService(config);
  const stats = new StatsService(config, reputation);
  const mode = new ModeService(config, reputation, metrics);
  const cfRanges = new CloudflareRangesService(config);
  const cloudflare = new CloudflareService(config, reputation, metrics);
  const firewall = new FirewallService(config, metrics, cfRanges);
  const resolver = new FakeResolver();
  const allowlist = new AllowlistService(config, reputation);
  allowlist.setResolver(resolver);
  await allowlist.refresh();
  const bots = new BotVerifierService(config, reputation);
  bots.setResolver(resolver);
  const bans = new BanService(config, reputation, firewall, cloudflare, metrics, alerts, stats);
  const scoring = new ScoringService(config, rules, reputation, bans, allowlist, bots, mode, metrics, stats);
  scoring.onModuleInit();
  const analyzer = new LogAnalyzerService(config, rules, scoring, cfRanges, metrics, stats);

  const req = (r: Partial<RawRequest> & { ip: string }): BuiltContext => {
    const b = buildContext(
      {
        method: 'GET',
        uri: '/',
        host: 'orleansembroidery.com',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36',
        acceptLanguage: 'es-ES,es;q=0.9',
        ...r,
      },
      config,
      (ip) => cfRanges.isCloudflare(ip),
    );
    if (!b) throw new Error(`IP inválida en test: ${r.ip}`);
    return b;
  };

  return { config, rules, redis, reputation, metrics, stats, mode, cfRanges, allowlist, bots, resolver, bans, scoring, analyzer, req };
}

export const NORMAL_PATHS = [
  '/',
  '/shop/',
  '/product/camiseta-bordada-azul/',
  '/product-category/gorras/',
  '/cart/',
  '/checkout/',
  '/my-account/',
  '/?wc-ajax=get_refreshed_fragments',
  '/?wc-ajax=add_to_cart',
  '/wp-json/wc/store/v1/cart',
  '/wp-json/wp/v2/pages?per_page=10',
  '/wp-admin/admin-ajax.php',
  '/wp-cron.php?doing_wp_cron=1727700000.1234',
  '/sitemap_index.xml',
  '/product-sitemap.xml',
  '/robots.txt',
  '/?s=union+jack+shirt',
  '/?s=o%27neill+sweater',
  '/?post_type=product&s=select+color',
  '/site1/',
  '/site1/wp-admin/',
  '/site2/wp-admin/admin-ajax.php',
  '/site1/wp-login.php',
  '/wp-admin/about.php',
  '/wp-admin/upload.php',
  '/wp-admin/post.php?post=123&action=edit',
  '/wp-admin/admin.php?page=wc-orders',
  '/wp-login.php',
  '/wp-content/uploads/2024/05/logo.png',
  '/?elementor-preview=123&ver=1727700000',
  '/wp-admin/admin-ajax.php?action=elementor_ajax',
  '/.well-known/acme-challenge/abcDEF123-token',
];
