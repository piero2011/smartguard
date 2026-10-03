import { Controller, Delete, Get, HttpCode, Post, UseGuards } from '@nestjs/common';
import { AdminAuthGuard } from '../common/security';
import { ConfigService } from '../config/config.service';
import { RulesService } from '../rules/rules.service';
import { BanService } from '../ban/ban.service';
import { AllowlistService } from '../whitelist/allowlist.service';
import { ReputationService } from '../reputation/reputation.service';
import { HOST_FIELD_PREFIX, MAX_BAN_SEC } from '../reputation/reputation.store';
import { ModeService } from '../scoring/mode.service';
import { CloudflareRangesService } from '../cloudflare/cloudflare-ranges.service';
import { ParsedIp, ipKey, parseIp } from '../common/ip.util';
import { formatDuration, parseDuration } from '../common/uri.util';
import { StatsService, currentMinute } from '../stats/stats.service';
import { AllowValueParam, Infer, IpParam, ValidBody, ValidQuery } from '../common/validation';
import { AllowBody, BanBody, BotBody, BotQuery, EventsPageQuery, EventsQuery, IpInfoQuery, PanelRuleBody, PanelRuleQuery, RecentQuery, ListQuery, LookupQuery, ModeBody, NetworkBody, NetworkQuery, StatsQuery, UnbanQuery } from './admin.schemas';
import { BlocklistService } from '../blocklist/blocklist.service';
import { IpInfoService } from '../ipinfo/ipinfo.service';
import { ApiError } from '../common/api-error';
import { SystemInfoService } from './system-info.service';
import { detectDeployment } from '../common/deployment';
import { NginxSitesService } from './nginx-sites.service';
import { parseRuleDef } from '../config/config.service';
import { compileSafeRegex } from '../rules/regex-safety';
import { RuleDef } from '../rules/rule.types';

const MAX_PANEL_RULES = 200;
/** Minutos de estadísticas que se conservan (TTL de stats:{minuto} y top:* en el almacén: 48 h). */
const STATS_RETENTION_MIN = 2 * 24 * 60;

/** Peticiones de un visitante normal: una regla del panel que las alcance afectaría a todo el mundo. */
const NORMAL_SAMPLES: Record<RuleDef['target'] & string, string[]> = {
  path: ['/', '/index.php', '/wp-login.php', '/wp-admin/admin-ajax.php', '/wp-json/', '/shop/', '/cart/', '/checkout/', '/my-account/'],
  uri: ['/', '/index.php', '/?wc-ajax=get_refreshed_fragments', '/wp-admin/admin-ajax.php', '/shop/?orderby=price'],
  query: ['wc-ajax=get_refreshed_fragments', 'orderby=price&paged=2', 's=camiseta'],
  ua: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  ],
  method: ['GET', 'POST'],
};

/** Devuelve el ejemplo de tráfico normal que la regla alcanzaría, o null. Las excepciones (allow) no se comprueban. */
export function tooBroad(def: RuleDef): string | null {
  if (def.action === 'allow' || def.enabled === false) return null;
  const regex = new RegExp(def.pattern, def.flags ?? 'i');
  const methods = def.methods?.length ? new Set(def.methods) : null;
  // una regla limitada a métodos que un visitante no usa (p. ej. solo PUT) no afecta al tráfico normal
  if (def.target !== 'method' && methods && !methods.has('GET') && !methods.has('POST') && !methods.has('ANY')) return null;
  return NORMAL_SAMPLES[def.target ?? 'path'].find((s) => regex.test(s)) ?? null;
}
import { logger } from '../common/logger';

/**
 * API administrativa (punto 40). Solo loopback + Bearer ADMIN_TOKEN + rate limit.
 * Acceso remoto: túnel SSH (ssh -L 3100:127.0.0.1:3100 usuario@vps). Nunca exponer a Internet.
 */
@Controller('admin')
@UseGuards(AdminAuthGuard)
export class AdminController {
  constructor(
    private readonly config: ConfigService,
    private readonly rules: RulesService,
    private readonly bans: BanService,
    private readonly allowlist: AllowlistService,
    private readonly reputation: ReputationService,
    private readonly mode: ModeService,
    private readonly cfRanges: CloudflareRangesService,
    private readonly blocklist: BlocklistService,
    private readonly ipinfo: IpInfoService,
    private readonly system: SystemInfoService,
    private readonly nginxSites: NginxSitesService,
    private readonly statsService: StatsService,
  ) {}

  private key(ip: ParsedIp): string {
    return ipKey(ip, this.config.env.ipv6Prefix);
  }

  @Get('bans')
  async listBans(@ValidQuery(ListQuery) q: Infer<typeof ListQuery>): Promise<unknown> {
    const audit = q.audit === true;
    const [items, total] = await Promise.all([this.bans.list(audit, q.offset ?? 0, q.limit ?? 100), this.bans.count(audit)]);
    return { audit, total, items };
  }

  /** Explicación completa de por qué una IP tiene el score/estado que tiene (punto 83). */
  @Get('ip/:ip')
  async inspect(@IpParam('ip') ip: ParsedIp): Promise<unknown> {
    const key = this.key(ip);
    const [state, ban, auditBan, allowType] = await Promise.all([
      this.reputation.call((s) => s.getIpState(key)),
      this.bans.getBan('ip', key, false),
      this.bans.getBan('ip', key, true),
      Promise.resolve(this.allowlist.classify(ip)),
    ]);
    const now = Date.now();
    const decayPerMin = this.config.env.decayPerMinute;
    const current = state ? Math.max(0, state.score - (Math.max(0, now - (state.updatedAt ?? now)) / 60_000) * decayPerMin) : 0;

    // Agregado de motivos (dentro de la ventana guardada)
    const agg = new Map<string, number>();
    for (const r of state?.reasons ?? []) {
      for (const part of r.reason.split(',')) {
        const m = /^(.+?)\+(\d+(?:\.\d+)?)$/.exec(part);
        if (m) agg.set(m[1]!, (agg.get(m[1]!) ?? 0) + Number(m[2]));
      }
    }
    const sum = [...agg.values()].reduce((a, b) => a + b, 0);
    const decay = Math.max(0, Math.round((sum - current) * 10) / 10);
    const activeBan = ban ?? null;
    const action = activeBan
      ? `BLOCK ${formatDuration(activeBan.durationSec)} (hasta ${new Date(activeBan.expiresAt).toISOString()})`
      : current >= this.config.env.scoreBlock
        ? 'RATE_LIMIT/RESTRICTION (score alto sin ban activo)'
        : current >= this.config.env.scoreRateLimit
          ? 'RATE_LIMIT'
          : current >= this.config.env.scoreObserve
            ? 'OBSERVE'
            : 'ALLOW';

    const lines = [
      `IP: ${ip.address}${key !== ip.address ? ` (clave ${key})` : ''}`,
      `Score: ${Math.round(current * 10) / 10}  (evidencia fuerte: ${Math.round((state?.strong ?? 0) * 10) / 10})`,
      allowType ? `Allowlist: ${allowType} (nunca se bloquea)` : '',
      '',
      'Reasons:',
      ...[...agg.entries()].sort((a, b) => b[1] - a[1]).map(([id, v]) => `  ${id} +${v}`),
      decay > 0 ? `  decay -${decay}` : '',
      '',
      'Action:',
      `  ${action}`,
      auditBan ? `  (AUDIT: se habría baneado ${formatDuration(auditBan.durationSec)} por: ${auditBan.reasons.join(', ')})` : '',
      state?.recidivism ? `Reincidencia: ${state.recidivism} ban(es) en ${formatDuration(this.config.env.recidivismTtlSec)}` : '',
    ].filter((l, i, arr) => l !== '' || (arr[i - 1] !== '' && i > 0));

    return {
      ip: ip.address,
      key,
      viaCloudflareRange: this.cfRanges.isCloudflare(ip),
      allowlist: allowType,
      score: Math.round(current * 100) / 100,
      state,
      reasons: Object.fromEntries(agg),
      decay,
      ban: activeBan,
      auditBan,
      explanation: lines.join('\n'),
    };
  }

  @Post('ban')
  async ban(@ValidBody(BanBody) dto: Infer<typeof BanBody>): Promise<unknown> {
    const ip = parseIp(dto.ip);
    if (!ip) throw new ApiError(400, 'INVALID_IP', 'Invalid IP address', { field: 'ip', value: dto.ip });
    const key = this.key(ip);
    if (this.cfRanges.isCloudflare(ip)) {
      throw new ApiError(400, 'CLOUDFLARE_IP', `${ip.address} belongs to Cloudflare: blocking it would block all your visitors`, { ip: ip.address });
    }
    const allowed = this.allowlist.lookup(ip.address).matches.filter((m) => m.target === 'client');
    if (allowed.length > 0) {
      throw new ApiError(409, 'IP_ALLOWLISTED', `${ip.address} is in ${allowed.map((m) => `${m.list} (${m.source})`).join(', ')}; remove it from the allowlist first`, {
        ip: ip.address,
        matches: allowed,
      });
    }
    const current = await this.bans.getBan('ip', key);
    if (current) {
      throw new ApiError(409, 'ALREADY_BANNED', `${key} is already blocked until ${new Date(current.expiresAt).toISOString()}`, {
        ip: ip.address,
        key,
        ban: current,
      });
    }
    const durationSec = Math.min(parseDuration(dto.duration, 3600), MAX_BAN_SEC);
    const record = await this.bans.ban({
      ip,
      ipKey: key,
      scope: 'ip',
      key,
      reason: dto.reason ? `manual: ${dto.reason}` : 'manual',
      reasons: ['manual'],
      score: 0,
      source: 'MANUAL',
      audit: false, // un ban manual es explícito: se aplica también en AUDIT (lo hace cumplir BlocklistService)
      durationSec,
      tcpIp: dto.firewall ? ip : null,
      forceCloudflare: dto.cloudflare === true,
    });
    await this.blocklist.refresh();
    return record;
  }

  @Delete('ban/:ip')
  async unban(@IpParam('ip') ip: ParsedIp, @ValidQuery(UnbanQuery) q: Infer<typeof UnbanQuery>): Promise<unknown> {
    const res = await this.bans.unban(ip, this.key(ip), { reset: q.reset !== false });
    await this.blocklist.refresh();
    return res;
  }

  /** Bots bloqueados a mano por nombre (texto del User-Agent). Se aplican también en AUDIT. */
  @Get('blocked-bots')
  listBlockedBots(): unknown {
    return { items: this.blocklist.listBots() };
  }

  @Post('blocked-bots')
  async blockBot(@ValidBody(BotBody) dto: Infer<typeof BotBody>): Promise<unknown> {
    return this.blocklist.addBot(dto.pattern, dto.note ?? '', dto.ttl ? parseDuration(dto.ttl, 0) : undefined);
  }

  @Delete('blocked-bots')
  async unblockBot(@ValidQuery(BotQuery) q: Infer<typeof BotQuery>): Promise<unknown> {
    return { removed: await this.blocklist.removeBot(q.pattern) };
  }

  @Get('allow')
  listAllow(): unknown {
    return this.allowlist.list();
  }

  @Post('allow')
  async allow(@ValidBody(AllowBody) dto: Infer<typeof AllowBody>): Promise<unknown> {
    // Los conflictos (ya está en una lista) los lanza el servicio como 409 con la lista concreta
    const entry = await this.allowlist.add(
      dto.value,
      dto.type ?? 'ADMIN_ALLOWLIST',
      dto.target ?? 'client',
      dto.note ?? '',
      dto.ttl ? parseDuration(dto.ttl, 0) : undefined,
    );
    // Permitir una IP suele ir acompañado de desbloquearla
    const ip = entry.kind === 'cidr' && dto.unban !== false ? parseIp(entry.value.split('/')[0]) : null;
    const single = entry.value.endsWith('/32') || entry.value.endsWith('/128');
    const unban = ip && single ? await this.bans.unban(ip, this.key(ip)) : undefined;
    if (unban) await this.blocklist.refresh();
    return { entry, unban };
  }

  /**
   * ¿Dónde está este valor? Allowlists (lista, origen, por qué coincide), ban activo, would-ban de
   * AUDIT, score actual y si es una IP de Cloudflare. Acepta IP, CIDR, dominio, *.dominio o URL.
   */
  @Get('lookup')
  async lookup(@ValidQuery(LookupQuery) q: Infer<typeof LookupQuery>): Promise<unknown> {
    const res = this.allowlist.lookup(q.value);
    if (!res.normalized) throw new ApiError(400, 'INVALID_VALUE', 'Invalid value (use IP, CIDR, domain, *.domain or site URL)', { value: q.value });
    let ban = null;
    let auditBan = null;
    let fingerprintBans = 0;
    let score: number | null = null;
    let isCloudflare = false;
    let key: string | null = null;
    if (res.isIp) {
      const ip = parseIp(res.normalized.split('/')[0])!;
      key = this.key(ip);
      isCloudflare = this.cfRanges.isCloudflare(ip);
      const k = key;
      [ban, auditBan] = await Promise.all([this.bans.getBan('ip', k, false), this.bans.getBan('ip', k, true)]);
      const all = await this.bans.list(false, 0, 5000);
      fingerprintBans = all.filter((b) => b.scope === 'fp' && b.ip === ip.address).length;
      const state = await this.reputation.call((s) => s.getIpState(k));
      if (state) {
        const now = Date.now();
        score = Math.max(0, state.score - (Math.max(0, now - (state.updatedAt ?? now)) / 60_000) * this.config.env.decayPerMinute);
        score = Math.round(score * 10) / 10;
      }
    }
    return {
      input: res.input,
      normalized: res.normalized,
      kind: res.kind,
      isIp: res.isIp,
      key,
      isCloudflare,
      allowlisted: res.matches.length > 0,
      allowlist: res.matches,
      banned: !!ban,
      ban,
      auditBan,
      fingerprintBans,
      score,
    };
  }

  /** Redes completas (ASN) bloqueadas a mano: todos los rangos del proveedor. Se aplican también en AUDIT. */
  @Get('blocked-networks')
  listBlockedNetworks(): unknown {
    return { items: this.blocklist.listNetworks() };
  }

  @Post('blocked-networks')
  async blockNetwork(@ValidBody(NetworkBody) dto: Infer<typeof NetworkBody>): Promise<unknown> {
    if (!dto.ip && !dto.asn) throw new ApiError(400, 'VALIDATION', 'ip or asn: required', { field: 'ip', reason: 'required' });
    return this.blocklist.addNetwork({ ip: dto.ip, asn: dto.asn }, dto.note ?? '');
  }

  @Delete('blocked-networks')
  async unblockNetwork(@ValidQuery(NetworkQuery) q: Infer<typeof NetworkQuery>): Promise<unknown> {
    return { removed: await this.blocklist.removeNetwork(q.asn) };
  }

  /** A quién pertenece cada IP (red/ASN, organización, país de registro, ¿hosting?). Para el panel. */
  @Get('ipinfo')
  async ipInfo(@ValidQuery(IpInfoQuery) q: Infer<typeof IpInfoQuery>): Promise<unknown> {
    return { items: await this.ipinfo.lookupMany(q.ips.split(',')) };
  }

  @Delete('allow/:value')
  async unallow(@AllowValueParam('value') value: string): Promise<unknown> {
    return { removed: await this.allowlist.remove(value) };
  }

  @Get('stats')
  async stats(@ValidQuery(StatsQuery) q: Infer<typeof StatsQuery>): Promise<unknown> {
    const now = currentMinute();
    let minutes = q.minutes ?? 60;
    let end = now;
    if (q.from !== undefined || q.to !== undefined) {
      // Rango de fechas: se recorta a lo que se conserva (los contadores por minuto caducan a las 48 h).
      end = q.to === undefined ? now : Math.min(now, currentMinute(Number(q.to)));
      const oldest = now - STATS_RETENTION_MIN + 1;
      const start = Math.max(oldest, q.from === undefined ? end - minutes + 1 : currentMinute(Number(q.from)));
      if (start > end) {
        throw new ApiError(400, 'INVALID_RANGE', 'Invalid date range: "from" must be before "to", within the last 48 hours', { from: q.from, to: q.to });
      }
      minutes = end - start + 1;
    }
    const mins = Array.from({ length: minutes }, (_, i) => end - minutes + 1 + i);
    const hours = [...new Set(mins.map((m) => Math.floor((m * 60) / 3600)))];
    // Un sitio puede tener varios dominios (www, alias): se agrupan bajo su nombre principal.
    const groups = await this.nginxSites.groups();
    const primaryOf = new Map<string, string>();
    for (const [primary, all] of groups) for (const n of all) primaryOf.set(n, primary);
    const names = q.host ? (groups.get(q.host) ?? [q.host]) : [];
    const [buckets, activeIps, topPaths, topIps, topRules, bansActive, wouldBans] = await Promise.all([
      this.reputation.call((s) => s.readStats(mins)),
      this.reputation.call((s) => s.readActiveIps(mins.slice(-5), names)),
      this.readTop('paths', hours, names),
      this.readTop('ips', hours, names),
      this.readTop('rules', hours, names),
      this.bans.count(false),
      this.bans.count(true),
    ]);
    // Cada minuto guarda los contadores globales y, con prefijo "h:<host>:", los de cada sitio.
    // Aquí se deja en cada tramo solo lo pedido (un sitio o el total) y se anota qué sitios tienen datos.
    const seen = new Map<string, number>();
    for (const b of buckets) {
      const kept: Record<string, number> = {};
      for (const [k, v] of Object.entries(b.fields)) {
        if (k.startsWith(HOST_FIELD_PREFIX)) {
          const cut = k.lastIndexOf(':');
          const host = k.slice(HOST_FIELD_PREFIX.length, cut);
          const site = primaryOf.get(host) ?? host;
          seen.set(site, (seen.get(site) ?? 0) + v);
          // con un sitio elegido se suman los contadores de todos sus dominios
          if (names.includes(host)) kept[k.slice(cut + 1)] = (kept[k.slice(cut + 1)] ?? 0) + v;
        } else if (!q.host) kept[k] = v;
      }
      b.fields = kept;
    }
    const totals: Record<string, number> = {};
    for (const b of buckets) for (const [k, v] of Object.entries(b.fields)) totals[k] = (totals[k] ?? 0) + v;
    // Serie para el gráfico del panel: se agrupa en tramos para que 24 h no sean 1440 puntos.
    const step = minutes <= 90 ? 1 : minutes <= 360 ? 5 : minutes <= 1440 ? 15 : 30;
    const grouped = new Map<number, Record<string, number>>();
    for (const b of buckets) {
      const t = Math.floor(b.minute / step) * step * 60_000;
      const g = grouped.get(t) ?? {};
      for (const [k, v] of Object.entries(b.fields)) g[k] = (g[k] ?? 0) + v;
      grouped.set(t, g);
    }
    const series = [...grouped.entries()].map(([t, fields]) => ({ t, ...fields }));
    const last = buckets.slice(-5);
    const perMin = (field: string) => Math.round(last.reduce((a, b) => a + (b.fields[field] ?? 0), 0) / Math.max(1, last.length));
    return {
      mode: this.mode.audit ? 'AUDIT' : 'ENFORCE',
      windowMinutes: minutes,
      /** periodo realmente devuelto (ms), ya recortado a lo que se conserva */
      from: mins[0]! * 60_000,
      to: (end + 1) * 60_000,
      host: q.host ?? '',
      /** sitios con datos en el periodo, del que más tiene al que menos */
      hosts: [...seen.entries()].sort((a, b) => b[1] - a[1]).map(([h]) => h),
      requestsPerMin: perMin('requests'),
      logLinesPerMin: perMin('log_lines'),
      activeIps5m: activeIps,
      bansActive,
      wouldBansActive: wouldBans,
      totals,
      stepMinutes: step,
      series,
      topPaths,
      topIps,
      topRules,
      degraded: this.reputation.degraded,
    };
  }

  /** "Top" de un sitio (sumando todos sus dominios) o, sin dominios, el global. */
  private async readTop(kind: 'paths' | 'ips' | 'rules', hours: number[], names: string[]): Promise<{ member: string; score: number }[]> {
    if (names.length === 0) return this.reputation.call((s) => s.readTop(kind, hours, 15));
    const agg = new Map<string, number>();
    for (const rows of await Promise.all(names.map((n) => this.reputation.call((s) => s.readTop(kind, hours, 15, n))))) {
      for (const r of rows) agg.set(r.member, (agg.get(r.member) ?? 0) + r.score);
    }
    return [...agg.entries()]
      .map(([member, score]) => ({ member, score }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 15);
  }

  /**
   * Tráfico reciente: las últimas peticiones que SmartGuard evaluó (también las permitidas, que no
   * generan evento de seguridad) y las IPs activas en los últimos 5 minutos. Solo en memoria.
   */
  @Get('recent')
  async recent(@ValidQuery(RecentQuery) q: Infer<typeof RecentQuery>): Promise<unknown> {
    const names = q.host ? ((await this.nginxSites.groups()).get(q.host) ?? [q.host]) : [];
    const all = this.statsService.recentRequests(names);
    const since = Date.now() - 5 * 60_000;
    const ips = new Map<string, { ip: string; ipKey: string; country?: string; requests: number; lastSeen: number; lastPath: string; userAgent: string; blocked: number }>();
    for (const r of all) {
      if (r.t < since) break; // ordenado de más nuevo a más antiguo
      const cur = ips.get(r.ipKey);
      if (cur) {
        cur.requests++;
        if (r.action === 'BLOCK' || r.action === 'RATE_LIMIT') cur.blocked++;
      } else {
        ips.set(r.ipKey, { ip: r.ip, ipKey: r.ipKey, country: r.country, requests: 1, lastSeen: r.t, lastPath: r.path, userAgent: r.userAgent, blocked: r.action === 'BLOCK' || r.action === 'RATE_LIMIT' ? 1 : 0 });
      }
    }
    return {
      host: q.host ?? '',
      /** entradas guardadas (como mucho 300 por sitio) */
      stored: all.length,
      activeIps: [...ips.values()].sort((a, b) => b.requests - a.requests).slice(0, 100),
      items: all.slice(0, q.limit ?? 200),
    };
  }

  @Get('events')
  async events(@ValidQuery(EventsQuery) q: Infer<typeof EventsQuery>): Promise<unknown> {
    const filtered = q.from !== undefined || q.to !== undefined || q.ip !== undefined;
    const query = { from: q.from === undefined ? undefined : Number(q.from), to: q.to === undefined ? undefined : Number(q.to), ip: q.ip };
    return this.reputation.call((s) => s.listEvents(q.limit ?? 100, filtered ? query : undefined));
  }

  /** Versión instalada y lo que ocupa SmartGuard: disco por carpeta, memoria del proceso y Redis. */
  @Get('system')
  async systemInfo(): Promise<unknown> {
    return this.system.info();
  }

  /** Sitios configurados en Nginx y cuáles incluyen los fragmentos de SmartGuard en su vhost. */
  @Get('sites')
  async sites(): Promise<unknown> {
    return this.nginxSites.list();
  }

  @Get('events/page')
  async eventsPage(@ValidQuery(EventsPageQuery) q: Infer<typeof EventsPageQuery>): Promise<unknown> {
    const query = {
      from: q.from === undefined ? undefined : Number(q.from),
      to: q.to === undefined ? undefined : Number(q.to),
      kind: q.kind,
      hosts: q.host ? ((await this.nginxSites.groups()).get(q.host) ?? [q.host]) : undefined,
      text: q.q?.toLowerCase() || undefined,
    };
    return this.reputation.call((s) => s.pageEvents(q.limit ?? 50, query, q.cursor));
  }

  @Get('rules')
  rulesList(): unknown {
    const panelIds = new Set(this.config.panelRules.map((r) => r.id));
    return {
      ...this.rules.info(),
      rules: this.rules.listRules().map((r) => ({
        id: r.id,
        name: r.name,
        /** panel = creada desde el panel (se puede editar allí) · file = de rules.yaml / rules.d */
        source: panelIds.has(r.id) ? 'panel' : 'file',
        target: r.target,
        pattern: r.regex.source,
        score: r.score,
        severity: r.severity,
        confidence: r.confidence,
        category: r.category,
        action: r.action,
        phase: r.phase,
        methods: r.methods ? [...r.methods] : ['ANY'],
        status: r.status ? [...r.status] : undefined,
      })),
      behavior: this.config.rules.behavior,
    };
  }

  /** Reglas creadas desde el panel (incluidas las desactivadas, que no aparecen en /admin/rules). */
  @Get('panel-rules')
  panelRules(): unknown {
    return { items: this.config.panelRules, max: MAX_PANEL_RULES };
  }

  /** Crea una regla del panel o reemplaza la que tenga ese id. Se valida y compila antes de guardarla. */
  @Post('panel-rules')
  @HttpCode(200)
  async savePanelRule(@ValidBody(PanelRuleBody) dto: Infer<typeof PanelRuleBody>): Promise<unknown> {
    let def: RuleDef;
    try {
      def = parseRuleDef({ ...dto, methods: dto.methods ? dto.methods.toUpperCase().split(',') : undefined }, 'panel');
      compileSafeRegex(def.pattern, def.flags ?? 'i');
    } catch (e) {
      throw new ApiError(400, 'RULE_REJECTED', `Rule rejected: ${(e as Error).message}`, { error: (e as Error).message });
    }
    if (this.config.fileRules.some((r) => r.id === def.id)) {
      throw new ApiError(409, 'RULE_ID_TAKEN', `A built-in rule already uses the id "${def.id}"`, { id: def.id });
    }
    const broad = tooBroad(def);
    if (broad) throw new ApiError(400, 'RULE_TOO_BROAD', `The pattern also matches normal traffic (${broad}); it would block or penalize every visitor`, { sample: broad });
    const others = this.config.panelRules.filter((r) => r.id !== def.id);
    if (others.length >= MAX_PANEL_RULES) throw new ApiError(400, 'RULE_LIMIT', `At most ${MAX_PANEL_RULES} panel rules`, { max: MAX_PANEL_RULES });
    await this.applyPanelRules([...others, def]);
    logger.warn(`Regla del panel guardada: ${def.id}`, 'Admin');
    return { rule: def };
  }

  @Delete('panel-rules')
  async deletePanelRule(@ValidQuery(PanelRuleQuery) q: Infer<typeof PanelRuleQuery>): Promise<unknown> {
    if (!this.config.panelRules.some((r) => r.id === q.id)) throw new ApiError(404, 'RULE_NOT_FOUND', `No panel rule with id "${q.id}"`, { id: q.id });
    await this.applyPanelRules(this.config.panelRules.filter((r) => r.id !== q.id));
    logger.warn(`Regla del panel eliminada: ${q.id}`, 'Admin');
    return { removed: true };
  }

  /** Activa el nuevo conjunto de reglas del panel; si no compila o no se puede guardar, queda el anterior. */
  private async applyPanelRules(list: RuleDef[]): Promise<void> {
    const prev = this.config.rules;
    const prevPanel = this.config.panelRules;
    this.config.rules = { ...prev, rules: [...this.config.fileRules, ...list] };
    try {
      this.rules.compile();
      await this.config.writePanelRules(list);
    } catch (e) {
      this.config.rules = prev;
      this.config.panelRules = prevPanel;
      this.rules.compile();
      throw new ApiError(400, 'RULE_REJECTED', `Rule rejected, previous rules kept: ${(e as Error).message}`, { error: (e as Error).message });
    }
  }

  @Post('rules/reload')
  @HttpCode(200)
  async reload(): Promise<unknown> {
    const prev = { rules: this.config.rules, fileRules: this.config.fileRules, panelRules: this.config.panelRules, sites: this.config.sites, bots: this.config.bots };
    try {
      await this.config.loadFiles();
      const summary = this.rules.compile();
      logger.warn(`Reglas recargadas: ${JSON.stringify(summary)}`, 'Admin');
      return { ok: true, ...summary };
    } catch (e) {
      // Restaurar configuración anterior: una regla mala nunca deja a SmartGuard sin reglas
      this.config.rules = prev.rules;
      this.config.fileRules = prev.fileRules;
      this.config.panelRules = prev.panelRules;
      this.config.sites = prev.sites;
      this.config.bots = prev.bots;
      this.rules.compile();
      throw new ApiError(400, 'RELOAD_REJECTED', `Reload rejected, previous configuration kept: ${(e as Error).message}`, { error: (e as Error).message });
    }
  }

  @Get('mode')
  getMode(): unknown {
    // deployment: el panel adapta lo que ofrece según sea una instalación en el sistema o en Docker
    return { audit: this.mode.audit, mode: this.mode.audit ? 'AUDIT' : 'ENFORCE', deployment: detectDeployment() };
  }

  @Post('mode')
  @HttpCode(200)
  async setMode(@ValidBody(ModeBody) dto: Infer<typeof ModeBody>): Promise<unknown> {
    await this.mode.set(dto.audit);
    return { audit: this.mode.audit, mode: this.mode.audit ? 'AUDIT' : 'ENFORCE' };
  }
}
