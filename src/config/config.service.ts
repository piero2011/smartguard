import { Injectable } from '@nestjs/common';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { EnvConfig, loadEnv } from './env';
import { EVENT_CATEGORIES, EventCategory } from '../common/types';
import {
  BadBotDef,
  BehaviorConfig,
  BehaviorSignal,
  BotDef,
  BotsFile,
  RuleDef,
  RulesFile,
  SiteConfig,
  SitesFile,
} from '../rules/rule.types';
import { normalizeHost } from '../common/uri.util';

export const DEFAULT_BEHAVIOR: BehaviorConfig = {
  notFound: { score: 1, confidence: 'low' },
  notFoundBurst: { score: 5, confidence: 'medium', windowSec: 60, threshold: 20 },
  phpNotFound: { score: 10, confidence: 'medium' },
  pluginEnum: { score: 20, confidence: 'high', windowSec: 120, threshold: 10 },
  loginFailed: { score: 10, confidence: 'low', windowSec: 600, threshold: 8 },
  loginStuffing: { score: 20, confidence: 'high', windowSec: 600, threshold: 30 },
  rateLimited: { score: 2, confidence: 'low' },
  nginxDenied: { score: 3, confidence: 'medium' },
};

/**
 * Configuración completa: variables de entorno (secretos, umbrales) + YAML (reglas, sitios, bots).
 * Los YAML se leen de CONFIG_DIR (/etc/smartguard) con fallback a ./config del proyecto.
 */
@Injectable()
export class ConfigService {
  readonly env: EnvConfig;
  rules!: RulesFile;
  sites!: SitesFile;
  bots!: BotsFile;
  /** host normalizado → sitio */
  private hostIndex = new Map<string, SiteConfig>();

  constructor(env?: EnvConfig) {
    this.env = env ?? loadEnv();
  }

  /** Carga (o recarga) los YAML. Lanza si algún archivo es inválido: la configuración anterior sigue vigente. */
  async loadFiles(): Promise<void> {
    const [rulesRaw, sitesRaw, botsRaw] = await Promise.all([
      this.readYaml('rules.yaml'),
      this.readYaml('sites.yaml'),
      this.readYaml('bots.yaml'),
    ]);
    const rules = parseRulesFile(rulesRaw);
    // reglas adicionales en rules.d/*.yaml (personalizadas, preservadas por update.sh)
    for (const extra of await this.readRulesDir()) rules.rules.push(...extra);
    const sites = parseSitesFile(sitesRaw);
    const bots = parseBotsFile(botsRaw);

    const index = new Map<string, SiteConfig>();
    for (const s of sites.sites) {
      for (const h of [s.name, ...s.aliases]) index.set(h, s);
    }
    this.rules = rules;
    this.sites = sites;
    this.bots = bots;
    this.hostIndex = index;
  }

  /** Configuración cargada desde objetos (tests). */
  loadFromObjects(rules: unknown, sites: unknown, bots: unknown): void {
    this.rules = parseRulesFile(rules);
    this.sites = parseSitesFile(sites);
    this.bots = parseBotsFile(bots);
    this.hostIndex.clear();
    for (const s of this.sites.sites) for (const h of [s.name, ...s.aliases]) this.hostIndex.set(h, s);
  }

  siteForHost(host: string): SiteConfig | null {
    return this.hostIndex.get(host) ?? null;
  }

  configPath(file: string): string[] {
    return [path.join(this.env.configDir, file), path.join(process.cwd(), 'config', file)];
  }

  private async readYaml(file: string): Promise<unknown> {
    for (const p of this.configPath(file)) {
      try {
        const text = await fs.readFile(p, 'utf8');
        return parseYaml(text, { maxAliasCount: 50 });
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') continue;
        throw new Error(`Error leyendo ${p}: ${(e as Error).message}`);
      }
    }
    throw new Error(`No se encontró ${file} en ${this.configPath(file).join(' ni ')}`);
  }

  private async readRulesDir(): Promise<RuleDef[][]> {
    const dir = path.join(this.env.configDir, 'rules.d');
    let files: string[];
    try {
      files = (await fs.readdir(dir)).filter((f) => /\.ya?ml$/.test(f)).sort();
    } catch {
      return [];
    }
    const out: RuleDef[][] = [];
    for (const f of files) {
      const doc = parseYaml(await fs.readFile(path.join(dir, f), 'utf8')) as { rules?: unknown };
      out.push(parseRuleList(doc?.rules, `rules.d/${f}`));
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Parsers/validadores (sin dependencias; errores con contexto claro)
// ---------------------------------------------------------------------------

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const CONFIDENCES = new Set(['low', 'medium', 'high']);
const TARGETS = new Set(['path', 'query', 'uri', 'ua', 'method']);
const ACTIONS = new Set(['score', 'block', 'allow']);
const PHASES = new Set(['decision', 'analyzer', 'both']);

export function parseRuleDef(raw: unknown, where: string): RuleDef {
  if (!isObj(raw)) throw new Error(`${where}: la regla debe ser un objeto`);
  const id = String(raw.id ?? '');
  if (!/^[a-z0-9][a-z0-9_.-]{1,63}$/.test(id)) throw new Error(`${where}: id inválido "${id}" (a-z0-9_.- , 2-64)`);
  const ctx = `${where} [${id}]`;
  const pattern = String(raw.pattern ?? '');
  if (!pattern) throw new Error(`${ctx}: falta pattern`);
  const severity = String(raw.severity ?? 'medium');
  if (!SEVERITIES.has(severity)) throw new Error(`${ctx}: severity inválida`);
  const confidence = String(raw.confidence ?? (severity === 'critical' || severity === 'high' ? 'high' : 'medium'));
  if (!CONFIDENCES.has(confidence)) throw new Error(`${ctx}: confidence inválida`);
  const target = String(raw.target ?? 'path');
  if (!TARGETS.has(target)) throw new Error(`${ctx}: target inválido`);
  const action = String(raw.action ?? 'score');
  if (!ACTIONS.has(action)) throw new Error(`${ctx}: action inválida`);
  const phase = String(raw.phase ?? 'both');
  if (!PHASES.has(phase)) throw new Error(`${ctx}: phase inválida`);
  const category = String(raw.category ?? 'UNKNOWN') as EventCategory;
  if (!(EVENT_CATEGORIES as readonly string[]).includes(category)) throw new Error(`${ctx}: category inválida`);
  const score = Number(raw.score ?? 0);
  if (!Number.isFinite(score) || score < 0 || score > 1000) throw new Error(`${ctx}: score inválido`);
  const methods = Array.isArray(raw.methods) ? raw.methods.map((m) => String(m).toUpperCase()) : undefined;
  const status = Array.isArray(raw.status) ? raw.status.map((s) => Number(s)).filter((n) => n >= 100 && n <= 599) : undefined;
  return {
    id,
    name: String(raw.name ?? id),
    enabled: raw.enabled === undefined ? true : Boolean(raw.enabled),
    target: target as RuleDef['target'],
    pattern,
    flags: raw.flags === undefined ? 'i' : String(raw.flags),
    methods,
    score,
    severity: severity as RuleDef['severity'],
    confidence: confidence as RuleDef['confidence'],
    category,
    action: action as RuleDef['action'],
    ttl: raw.ttl === undefined ? undefined : Math.max(0, Number(raw.ttl)),
    status,
    phase: phase as RuleDef['phase'],
  };
}

function parseRuleList(raw: unknown, where: string): RuleDef[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) throw new Error(`${where}: "rules" debe ser una lista`);
  const seen = new Set<string>();
  return raw.map((r, i) => {
    const def = parseRuleDef(r, `${where}#${i}`);
    if (seen.has(def.id)) throw new Error(`${where}: id duplicado "${def.id}"`);
    seen.add(def.id);
    return def;
  });
}

function parseSignal(raw: unknown, def: BehaviorSignal): BehaviorSignal {
  if (!isObj(raw)) return def;
  const confidence = raw.confidence === undefined ? def.confidence : String(raw.confidence);
  if (!CONFIDENCES.has(confidence)) throw new Error('behavior: confidence inválida');
  return {
    score: raw.score === undefined ? def.score : Number(raw.score),
    confidence: confidence as BehaviorSignal['confidence'],
    windowSec: raw.windowSec === undefined ? def.windowSec : Number(raw.windowSec),
    threshold: raw.threshold === undefined ? def.threshold : Number(raw.threshold),
  };
}

export function parseRulesFile(raw: unknown): RulesFile {
  if (!isObj(raw)) throw new Error('rules.yaml: raíz inválida');
  const b = isObj(raw.behavior) ? raw.behavior : {};
  const behavior = {} as BehaviorConfig;
  for (const k of Object.keys(DEFAULT_BEHAVIOR) as (keyof BehaviorConfig)[]) {
    behavior[k] = parseSignal(b[k], DEFAULT_BEHAVIOR[k]);
  }
  return { version: Number(raw.version ?? 1), behavior, rules: parseRuleList(raw.rules, 'rules.yaml') };
}

export function parseSitesFile(raw: unknown): SitesFile {
  const root = isObj(raw) ? raw : {};
  const d = isObj(root.defaults) ? root.defaults : {};
  const defaults = {
    wordpress: d.wordpress === undefined ? true : Boolean(d.wordpress),
    multisite: Boolean(d.multisite ?? false),
    woocommerce: Boolean(d.woocommerce ?? false),
    xmlrpc: Boolean(d.xmlrpc ?? false),
  };
  const sitesRaw = isObj(root.sites) ? root.sites : {};
  const sites: SiteConfig[] = [];
  for (const [name, val] of Object.entries(sitesRaw)) {
    const host = normalizeHost(name);
    if (!host) throw new Error(`sites.yaml: host inválido "${name}"`);
    const s = isObj(val) ? val : {};
    const r = isObj(s.rules) ? s.rules : {};
    const overrides: Record<string, Partial<RuleDef>> = {};
    if (isObj(r.overrides)) {
      for (const [id, o] of Object.entries(r.overrides)) {
        if (!isObj(o)) continue;
        const ov: Partial<RuleDef> = {};
        if (o.score !== undefined) ov.score = Number(o.score);
        if (o.enabled !== undefined) ov.enabled = Boolean(o.enabled);
        if (o.action !== undefined) ov.action = String(o.action) as RuleDef['action'];
        if (o.confidence !== undefined) ov.confidence = String(o.confidence) as RuleDef['confidence'];
        overrides[id] = ov;
      }
    }
    sites.push({
      name: host,
      aliases: Array.isArray(s.aliases) ? s.aliases.map((a) => normalizeHost(String(a))).filter(Boolean) : [],
      wordpress: s.wordpress === undefined ? defaults.wordpress : Boolean(s.wordpress),
      multisite: s.multisite === undefined ? defaults.multisite : Boolean(s.multisite),
      woocommerce: s.woocommerce === undefined ? defaults.woocommerce : Boolean(s.woocommerce),
      xmlrpc: s.xmlrpc === undefined ? defaults.xmlrpc : Boolean(s.xmlrpc),
      rules: {
        disabled: Array.isArray(r.disabled) ? r.disabled.map(String) : [],
        overrides,
        extra: parseRuleList(r.extra, `sites.yaml:${host}`),
      },
    });
  }
  return { defaults, sites };
}

export function parseBotsFile(raw: unknown): BotsFile {
  const root = isObj(raw) ? raw : {};
  const verified: BotDef[] = (Array.isArray(root.verified) ? root.verified : []).map((b, i) => {
    if (!isObj(b)) throw new Error(`bots.yaml verified#${i}: inválido`);
    const verify = String(b.verify ?? 'fcrdns');
    if (verify !== 'fcrdns' && verify !== 'none') throw new Error(`bots.yaml ${String(b.id)}: verify inválido`);
    const domains = Array.isArray(b.domains) ? b.domains.map((d) => String(d).toLowerCase().replace(/^\.+/, '')) : [];
    if (verify === 'fcrdns' && domains.length === 0) throw new Error(`bots.yaml ${String(b.id)}: fcrdns requiere domains`);
    return { id: String(b.id), name: String(b.name ?? b.id), ua: String(b.ua), verify, domains };
  });
  const bad: BadBotDef[] = (Array.isArray(root.bad) ? root.bad : []).map((b, i) => {
    if (!isObj(b)) throw new Error(`bots.yaml bad#${i}: inválido`);
    return {
      id: String(b.id),
      ua: String(b.ua),
      score: Number(b.score ?? 15),
      confidence: String(b.confidence ?? 'medium') as BadBotDef['confidence'],
      category: String(b.category ?? 'BAD_BOT') as EventCategory,
    };
  });
  return { verified, bad };
}
