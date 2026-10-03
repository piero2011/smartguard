import { Injectable } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { compileSafeRegex } from './regex-safety';
import { BadBotDef, BotDef, CompiledRule, RuleDef, SiteConfig } from './rule.types';
import { RequestContext } from '../common/types';

export interface CompiledBot extends BotDef {
  regex: RegExp;
}
export interface CompiledBadBot extends BadBotDef {
  regex: RegExp;
}

export interface RuleEvaluation {
  matches: CompiledRule[];
  /** una regla "allow" coincidió: no se suman puntos por reglas */
  allowedBy: CompiledRule | null;
  /** alguna regla con action=block coincidió */
  blockNow: boolean;
}

interface CompiledSet {
  /** reglas para decisión en tiempo real */
  decision: CompiledRule[];
  /** reglas para el analizador de logs */
  analyzer: CompiledRule[];
}

const EMPTY_EVAL: RuleEvaluation = { matches: [], allowedBy: null, blockNow: false };

/**
 * Motor de reglas declarativo (punto 29): nada de if() encadenados, todo sale de rules.yaml.
 * Las regex se compilan UNA vez por recarga, validadas anti-ReDoS.
 * Reglas por sitio: el sitio puede desactivar, sobrescribir (score/acción/confianza) o añadir reglas;
 * una regla "extra" del sitio con el mismo id que una global la reemplaza.
 */
@Injectable()
export class RulesService {
  private global: CompiledSet = { decision: [], analyzer: [] };
  private perSite = new Map<string, CompiledSet>();
  private verifiedBots: CompiledBot[] = [];
  private badBots: CompiledBadBot[] = [];
  private loadedAt = 0;
  private ruleCount = 0;

  constructor(private readonly config: ConfigService) {}

  /** Compila todo; si algo falla lanza y el conjunto anterior permanece activo. */
  compile(): { rules: number; sites: number; bots: number } {
    const { rules, sites, bots } = this.config;
    const compiledGlobal = rules.rules.filter((r) => r.enabled !== false).map((r) => compileRule(r));
    const global = split(compiledGlobal);

    const perSite = new Map<string, CompiledSet>();
    for (const site of sites.sites) {
      perSite.set(site.name, split(buildSiteRules(rules.rules, site)));
    }
    const verifiedBots = bots.verified.map((b) => ({ ...b, regex: compileSafeRegex(b.ua, 'i') }));
    const badBots = bots.bad.map((b) => ({ ...b, regex: compileSafeRegex(b.ua, 'i') }));

    this.global = global;
    this.perSite = perSite;
    this.verifiedBots = verifiedBots;
    this.badBots = badBots;
    this.loadedAt = Date.now();
    this.ruleCount = compiledGlobal.length;
    return { rules: compiledGlobal.length, sites: perSite.size, bots: verifiedBots.length + badBots.length };
  }

  info(): { loadedAt: number; globalRules: number; sites: string[] } {
    return { loadedAt: this.loadedAt, globalRules: this.ruleCount, sites: [...this.perSite.keys()] };
  }

  listRules(site?: string): CompiledRule[] {
    const set = (site && this.perSite.get(site)) || this.global;
    const map = new Map<string, CompiledRule>();
    for (const r of [...set.decision, ...set.analyzer]) map.set(r.id, r);
    return [...map.values()];
  }

  evaluate(ctx: RequestContext, phase: 'decision' | 'analyzer', status?: number): RuleEvaluation {
    const set = this.perSite.get(ctx.site) ?? this.global;
    const list = phase === 'decision' ? set.decision : set.analyzer;
    if (list.length === 0) return EMPTY_EVAL;

    let matches: CompiledRule[] | null = null;
    let allowedBy: CompiledRule | null = null;
    let blockNow = false;
    const queryText = ctx.query ? `${ctx.query} ${ctx.decodedQuery}` : '';

    for (const rule of list) {
      if (rule.methods && !rule.methods.has(ctx.method)) continue;
      if (rule.status && (status === undefined || !rule.status.has(status))) continue;
      let subject: string;
      switch (rule.target) {
        case 'path':
          subject = ctx.path;
          break;
        case 'query':
          if (!queryText) continue;
          subject = queryText;
          break;
        case 'uri':
          subject = ctx.rawUri;
          break;
        case 'ua':
          subject = ctx.userAgent;
          break;
        case 'method':
          subject = ctx.method;
          break;
      }
      if (!rule.regex.test(subject)) continue;
      if (rule.action === 'allow') {
        allowedBy = rule;
        break;
      }
      (matches ??= []).push(rule);
      if (rule.action === 'block') blockNow = true;
    }
    if (allowedBy) return { matches: [], allowedBy, blockNow: false };
    if (!matches) return EMPTY_EVAL;
    return { matches, allowedBy: null, blockNow };
  }

  matchVerifiedBot(ua: string): CompiledBot | null {
    if (!ua) return null;
    for (const b of this.verifiedBots) if (b.regex.test(ua)) return b;
    return null;
  }

  matchBadBot(ua: string): CompiledBadBot | null {
    for (const b of this.badBots) if (b.regex.test(ua)) return b;
    return null;
  }
}

function compileRule(r: RuleDef): CompiledRule {
  let regex: RegExp;
  try {
    regex = compileSafeRegex(r.pattern, r.flags ?? 'i');
  } catch (e) {
    throw new Error(`Regla "${r.id}": ${(e as Error).message}`);
  }
  const methods = r.methods && r.methods.length > 0 && !r.methods.includes('ANY') ? new Set(r.methods) : null;
  return {
    id: r.id,
    name: r.name,
    target: r.target ?? 'path',
    regex,
    methods,
    score: r.score,
    severity: r.severity,
    confidence: r.confidence ?? 'medium',
    category: r.category,
    action: r.action ?? 'score',
    ttl: r.ttl ?? 0,
    status: r.status && r.status.length > 0 ? new Set(r.status) : null,
    phase: r.phase ?? 'both',
  };
}

function buildSiteRules(globalDefs: RuleDef[], site: SiteConfig): CompiledRule[] {
  const disabled = new Set(site.rules.disabled);
  const extraIds = new Set(site.rules.extra.map((r) => r.id));
  const out: CompiledRule[] = [];
  for (const def of globalDefs) {
    if (def.enabled === false || disabled.has(def.id) || extraIds.has(def.id)) continue;
    const ov = site.rules.overrides[def.id];
    const merged: RuleDef = ov ? { ...def, ...ov } : def;
    if (merged.enabled === false) continue;
    // XMLRPC habilitado en el sitio: la regla de "xmlrpc desactivado" no aplica
    if (site.xmlrpc && def.id === 'xmlrpc-disabled') continue;
    out.push(compileRule(merged));
  }
  for (const def of site.rules.extra) if (def.enabled !== false) out.push(compileRule(def));
  return out;
}

function split(rules: CompiledRule[]): CompiledSet {
  return {
    decision: rules.filter((r) => r.phase !== 'analyzer' && !r.status),
    analyzer: rules.filter((r) => r.phase !== 'decision'),
  };
}
