import { Controller, Delete, Get, HttpCode, Post, UseGuards } from '@nestjs/common';
import { AdminAuthGuard } from '../common/security';
import { ConfigService } from '../config/config.service';
import { RulesService } from '../rules/rules.service';
import { BanService } from '../ban/ban.service';
import { AllowlistService } from '../whitelist/allowlist.service';
import { ReputationService } from '../reputation/reputation.service';
import { MAX_BAN_SEC } from '../reputation/reputation.store';
import { ModeService } from '../scoring/mode.service';
import { CloudflareRangesService } from '../cloudflare/cloudflare-ranges.service';
import { ParsedIp, ipKey, parseIp } from '../common/ip.util';
import { formatDuration, parseDuration } from '../common/uri.util';
import { currentMinute } from '../stats/stats.service';
import { AllowValueParam, Infer, IpParam, ValidBody, ValidQuery } from '../common/validation';
import { AllowBody, BanBody, BotBody, BotQuery, EventsPageQuery, EventsQuery, IpInfoQuery, ListQuery, LookupQuery, ModeBody, NetworkBody, NetworkQuery, StatsQuery, UnbanQuery } from './admin.schemas';
import { BlocklistService } from '../blocklist/blocklist.service';
import { IpInfoService } from '../ipinfo/ipinfo.service';
import { ApiError } from '../common/api-error';
import { SystemInfoService } from './system-info.service';
import { NginxSitesService } from './nginx-sites.service';
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
    const minutes = q.minutes ?? 60;
    const now = currentMinute();
    const mins = Array.from({ length: minutes }, (_, i) => now - minutes + 1 + i);
    const hours = [...new Set(mins.map((m) => Math.floor((m * 60) / 3600)))];
    const [buckets, activeIps, topPaths, topIps, topRules, bansActive, wouldBans] = await Promise.all([
      this.reputation.call((s) => s.readStats(mins)),
      this.reputation.call((s) => s.readActiveIps(mins.slice(-5))),
      this.reputation.call((s) => s.readTop('paths', hours, 15)),
      this.reputation.call((s) => s.readTop('ips', hours, 15)),
      this.reputation.call((s) => s.readTop('rules', hours, 15)),
      this.bans.count(false),
      this.bans.count(true),
    ]);
    const totals: Record<string, number> = {};
    for (const b of buckets) for (const [k, v] of Object.entries(b.fields)) totals[k] = (totals[k] ?? 0) + v;
    // Serie para el gráfico del panel: se agrupa en tramos para que 24 h no sean 1440 puntos.
    const step = minutes <= 90 ? 1 : minutes <= 360 ? 5 : 15;
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
      text: q.q?.toLowerCase() || undefined,
    };
    return this.reputation.call((s) => s.pageEvents(q.limit ?? 50, query, q.cursor));
  }

  @Get('rules')
  rulesList(): unknown {
    return {
      ...this.rules.info(),
      rules: this.rules.listRules().map((r) => ({
        id: r.id,
        name: r.name,
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

  @Post('rules/reload')
  @HttpCode(200)
  async reload(): Promise<unknown> {
    const prev = { rules: this.config.rules, sites: this.config.sites, bots: this.config.bots };
    try {
      await this.config.loadFiles();
      const summary = this.rules.compile();
      logger.warn(`Reglas recargadas: ${JSON.stringify(summary)}`, 'Admin');
      return { ok: true, ...summary };
    } catch (e) {
      // Restaurar configuración anterior: una regla mala nunca deja a SmartGuard sin reglas
      this.config.rules = prev.rules;
      this.config.sites = prev.sites;
      this.config.bots = prev.bots;
      this.rules.compile();
      throw new ApiError(400, 'RELOAD_REJECTED', `Reload rejected, previous configuration kept: ${(e as Error).message}`, { error: (e as Error).message });
    }
  }

  @Get('mode')
  getMode(): unknown {
    return { audit: this.mode.audit, mode: this.mode.audit ? 'AUDIT' : 'ENFORCE' };
  }

  @Post('mode')
  @HttpCode(200)
  async setMode(@ValidBody(ModeBody) dto: Infer<typeof ModeBody>): Promise<unknown> {
    await this.mode.set(dto.audit);
    return { audit: this.mode.audit, mode: this.mode.audit ? 'AUDIT' : 'ENFORCE' };
  }
}
