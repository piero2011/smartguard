import { Component, computed, effect, inject, signal } from '@angular/core';
import { AllowList, Api, ApiErr, BanRecord, BlockedBot, BlockedNetwork, SecurityEvent, Stats, isPermanent } from './api.service';
import { I18n, TPipe } from './i18n';
import { EventFilter, Ui } from './ui';
import { IpComponent } from './ipinfo';
import { BlockButtonsComponent } from './block.component';

/** Resumen: tarjetas + top rutas / IPs / reglas */
@Component({
  selector: 'sg-overview',
  imports: [TPipe, IpComponent, BlockButtonsComponent],
  template: `
  @if (stats(); as s) {
    <div class="cards">
      @for (c of cards(s); track c.key) {
        <button type="button" class="stat" [title]="'ov.open' | t" (click)="c.open()"><b>{{ c.value }}</b><span>{{ c.key | t }}</span></button>
      }
    </div>
    <div class="grid3">
      <section class="card"><h2>{{ 'ov.topPaths' | t }}</h2>
        <table><tr><th>{{ 'ov.path' | t }}</th><th class="num">{{ 'ov.hits' | t }}</th></tr>
          @for (r of s.topPaths; track r.member) {
            <tr class="link" [title]="'ov.open' | t" (click)="ui.openEvents('all', r.member)"><td><code>{{ r.member }}</code></td><td class="num">{{ r.score }}</td></tr>
          }
          @empty { <tr><td colspan="2" class="muted">{{ 'common.none' | t }}</td></tr> }
        </table></section>
      <section class="card"><h2>{{ 'ov.topIps' | t }}</h2>
        <table><tr><th>IP</th><th class="num">{{ 'ov.points' | t }}</th><th></th></tr>
          @for (r of s.topIps; track r.member) {
            <tr><td class="ip"><sg-ip [ip]="r.member" /></td><td class="num">{{ r.score }}</td>
              <td class="actions"><button class="small" (click)="inspect(r.member)">{{ 'common.inspect' | t }}</button>
                <sg-block [ip]="r.member" [ipKey]="r.member" [userAgent]="lastUa()[r.member] ?? ''" /></td></tr>
          } @empty { <tr><td colspan="3" class="muted">{{ 'common.none' | t }}</td></tr> }
        </table></section>
      <section class="card"><h2>{{ 'ov.topRules' | t }}</h2>
        <table><tr><th>{{ 'ov.rule' | t }}</th><th class="num">{{ 'ov.hits' | t }}</th></tr>
          @for (r of s.topRules; track r.member) {
            <tr class="link" [title]="'ov.open' | t" (click)="ui.openEvents('all', r.member)"><td>{{ r.member }}</td><td class="num">{{ r.score }}</td></tr>
          }
          @empty { <tr><td colspan="2" class="muted">{{ 'common.none' | t }}</td></tr> }
        </table></section>
    </div>
  } @else { <p class="muted">{{ 'common.loading' | t }}</p> }
  `,
})
export class OverviewComponent {
  private readonly api = inject(Api);
  readonly ui = inject(Ui);
  readonly stats = signal<Stats | null>(null);
  /** clave de IP → su User-Agent más reciente (de los eventos), para poder bloquear el bot desde aquí */
  readonly lastUa = signal<Record<string, string>>({});

  constructor() {
    effect(() => {
      this.ui.changed();
      void this.load();
    });
  }

  async load(): Promise<void> {
    try {
      this.stats.set(await this.api.stats(60));
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
    try {
      const ua: Record<string, string> = {};
      // los eventos llegan del más reciente al más antiguo: se queda el primero de cada IP
      for (const e of await this.api.events(1000)) {
        if (!e.userAgent) continue;
        ua[e.ipKey ?? e.ip] ??= e.userAgent;
        ua[e.ip] ??= e.userAgent;
      }
      this.lastUa.set(ua);
    } catch {
      /* sin eventos no se ofrece "Bloquear bot" en esta tabla */
    }
  }

  /** Cada tarjeta abre el detalle de su contador: Eventos (ya filtrados) o Bloqueadas. */
  cards(s: Stats): { key: string; value: number; open: () => void }[] {
    const t = s.totals ?? {};
    const ev = (f: EventFilter) => () => this.ui.openEvents(f);
    return [
      { key: 'ov.decisions', value: s.requestsPerMin, open: ev('all') },
      { key: 'ov.logLines', value: s.logLinesPerMin, open: ev('log') },
      { key: 'ov.activeIps', value: s.activeIps5m, open: ev('all') },
      { key: 'ov.bans', value: s.bansActive, open: () => this.ui.openBans(false) },
      { key: 'ov.wouldBans', value: s.wouldBansActive, open: () => this.ui.openBans(true) },
      { key: 'ov.suspicious', value: t['action_observe'] ?? 0, open: ev('suspicious') },
      { key: 'ov.sg403', value: t['blocked_403'] ?? 0, open: ev('blocked') },
      { key: 'ov.sg429', value: t['limited_429'] ?? 0, open: ev('limited') },
      { key: 'ov.nginx403', value: t['log_403'] ?? 0, open: ev('st403') },
      { key: 'ov.nginx429', value: t['log_429'] ?? 0, open: ev('st429') },
      { key: 'ov.phpAvoided', value: t['php_avoided'] ?? 0, open: ev('denied') },
      { key: 'ov.wouldBlock', value: (t['would_block'] ?? 0) + (t['would_rate_limit'] ?? 0), open: ev('wouldBlock') },
    ];
  }

  async inspect(ip: string): Promise<void> {
    try {
      this.ui.inspect.set({ ip, text: (await this.api.explain(ip)).explanation });
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}

/** IPs bloqueadas (reales y, opcionalmente, simuladas en AUDIT) */
@Component({
  selector: 'sg-bans',
  imports: [TPipe, IpComponent],
  template: `
  <section class="card">
    <div class="row between">
      <h2>{{ 'bl.title' | t }} ({{ items().length }})</h2>
      <label class="check"><input type="checkbox" [checked]="showAudit()" (change)="showAudit.set($any($event.target).checked); load()">
        {{ 'bl.showAudit' | t }}</label>
    </div>
    <div class="scroll"><table>
      <tr><th>{{ 'bl.ip' | t }}</th><th class="num">{{ 'bl.score' | t }}</th><th>{{ 'bl.reason' | t }}</th><th>{{ 'bl.scope' | t }}</th>
        <th>{{ 'bl.source' | t }}</th><th class="num">{{ 'bl.count' | t }}</th><th>{{ 'bl.created' | t }}</th><th>{{ 'bl.expires' | t }}</th>
        <th>{{ 'bl.mode' | t }}</th><th>{{ 'bl.action' | t }}</th></tr>
      @for (b of items(); track b.scope + b.key + b.audit) {
        <tr>
          <td class="ip"><sg-ip [ip]="b.scope === 'ip' ? b.key : b.ip" /></td><td class="num">{{ b.score }}</td><td>{{ b.reason }}</td>
          <td>{{ b.scope === 'ip' ? 'IP' : 'IP+UA' }}</td><td>{{ b.source }}</td><td class="num">{{ b.banCount }}</td>
          <td>{{ i18n.date(b.createdAt) }}</td><td>{{ permanent(b.expiresAt) ? ('bl.never' | t) : i18n.date(b.expiresAt) }}</td>
          <td><span class="pill" [class.audit]="b.audit" [class.enforce]="!b.audit">{{ b.audit ? 'AUDIT' : 'ENFORCE' }}</span></td>
          <td class="actions">
            <button class="small" (click)="inspect(b.ip)">{{ 'common.inspect' | t }}</button>
            <button class="small primary" (click)="unblock(b)">{{ 'common.unblock' | t }}</button>
          </td>
        </tr>
      } @empty { <tr><td colspan="10" class="muted">{{ 'common.none' | t }}</td></tr> }
    </table></div>
  </section>
  `,
})
export class BansComponent {
  private readonly api = inject(Api);
  private readonly ui = inject(Ui);
  readonly i18n = inject(I18n);
  readonly items = signal<BanRecord[]>([]);
  readonly showAudit = this.ui.showAuditBans;
  readonly permanent = isPermanent;

  constructor() {
    effect(() => {
      this.ui.changed();
      void this.load();
    });
  }

  async load(): Promise<void> {
    try {
      const real = await this.api.bans(false);
      const audit = this.showAudit() ? (await this.api.bans(true)).items : [];
      this.items.set([...real.items, ...audit]);
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  async unblock(b: BanRecord): Promise<void> {
    if (!confirm(this.i18n.t('bl.confirmUnblock', { ip: b.ip }))) return;
    try {
      const r = await this.api.unban(b.ip, false);
      this.ui.notify('ok', () => this.i18n.t('mg.unblock.done', { ip: b.ip, fp: r.fingerprintBans }));
      this.ui.bump();
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  async inspect(ip: string): Promise<void> {
    try {
      this.ui.inspect.set({ ip, text: (await this.api.explain(ip)).explanation });
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}

interface AllowRow {
  value: string;
  list: string;
  target: 'client' | 'host';
  origin: string;
  resolved: string;
  removable: boolean;
}

/** Lista blanca: .env (solo lectura) + dinámica (se puede quitar) */
@Component({
  selector: 'sg-allowlist',
  imports: [TPipe],
  template: `
  <section class="card">
    <h2>{{ 'al.title' | t }} ({{ rows().length }})</h2>
    <div class="scroll"><table>
      <tr><th>{{ 'al.value' | t }}</th><th>{{ 'al.list' | t }}</th><th>{{ 'al.target' | t }}</th><th>{{ 'al.origin' | t }}</th>
        <th>{{ 'al.resolved' | t }}</th><th></th></tr>
      @for (r of rows(); track r.list + r.target + r.value) {
        <tr>
          <td><code>{{ r.value }}</code></td><td>{{ ('list.' + r.list) | t }}</td><td>{{ ('al.target.' + r.target) | t }}</td>
          <td>{{ r.origin }}</td><td class="muted">{{ r.resolved }}</td>
          <td>@if (r.removable) { <button class="small" (click)="remove(r.value)">{{ 'common.remove' | t }}</button> }
              @else { <span class="muted">{{ 'al.editEnv' | t }}</span> }</td>
        </tr>
      } @empty { <tr><td colspan="6" class="muted">{{ 'common.none' | t }}</td></tr> }
    </table></div>
  </section>
  `,
})
export class AllowlistComponent {
  private readonly api = inject(Api);
  private readonly ui = inject(Ui);
  private readonly i18n = inject(I18n);
  readonly data = signal<AllowList | null>(null);

  constructor() {
    effect(() => {
      this.ui.changed();
      void this.load();
    });
  }

  rows(): AllowRow[] {
    const a = this.data();
    if (!a) return [];
    const out: AllowRow[] = [];
    for (const [list, values] of Object.entries(a.static ?? {})) {
      for (const v of values) {
        const builtin = v === '127.0.0.0/8' || v === '::1/128';
        out.push({
          value: v,
          list,
          target: list === 'ALLOW_HOSTS' ? 'host' : 'client',
          origin: this.i18n.t(builtin ? 'source.builtin' : 'source.env'),
          resolved: (a.resolvedDomains[v] ?? []).join(', '),
          removable: false,
        });
      }
    }
    for (const e of a.dynamic ?? []) {
      out.push({
        value: e.value,
        list: e.target === 'host' ? 'ALLOW_HOSTS' : e.type,
        target: e.target,
        origin: `${this.i18n.t('source.dynamic')}${e.note ? ' · ' + e.note : ''}${e.expiresAt ? ' · ' + this.i18n.t('common.until', { date: this.i18n.date(e.expiresAt) }) : ''}`,
        resolved: (a.resolvedDomains[e.value] ?? []).join(', '),
        removable: true,
      });
    }
    return out;
  }

  async load(): Promise<void> {
    try {
      this.data.set(await this.api.allowlist());
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  async remove(value: string): Promise<void> {
    if (!confirm(this.i18n.t('al.confirmRemove', { value }))) return;
    try {
      await this.api.unallow(value);
      this.ui.notify('ok', () => this.i18n.t('al.removed', { value }));
      this.ui.bump();
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}

/** Redes completas (ASN) bloqueadas: lista y baja. Se bloquean desde una fila de Eventos o del Resumen. */
@Component({
  selector: 'sg-blocked-networks',
  imports: [TPipe],
  template: `
  <section class="card">
    <h2>{{ 'net.title' | t }} ({{ items().length }})</h2>
    <p class="muted">{{ 'net.hint' | t }}</p>
    <div class="scroll"><table>
      <tr><th>{{ 'net.org' | t }}</th><th>ASN</th><th>{{ 'ev.country' | t }}</th><th class="num">{{ 'net.ranges' | t }}</th>
        <th>{{ 'bl.created' | t }}</th><th>{{ 'net.updated' | t }}</th><th></th></tr>
      @for (n of items(); track n.asn) {
        <tr><td>{{ n.org }}</td><td><code>AS{{ n.asn }}</code></td><td>{{ n.country }}</td><td class="num">{{ n.prefixCount }}</td>
          <td>{{ i18n.date(n.createdAt) }}</td><td>{{ i18n.date(n.fetchedAt) }}</td>
          <td class="actions"><button class="small primary" (click)="remove(n)">{{ 'common.unblock' | t }}</button></td></tr>
      } @empty { <tr><td colspan="7" class="muted">{{ 'common.none' | t }}</td></tr> }
    </table></div>
  </section>
  `,
})
export class BlockedNetworksComponent {
  private readonly api = inject(Api);
  private readonly ui = inject(Ui);
  readonly i18n = inject(I18n);
  readonly items = signal<BlockedNetwork[]>([]);

  constructor() {
    effect(() => {
      this.ui.changed();
      void this.load();
    });
  }

  async load(): Promise<void> {
    try {
      this.items.set((await this.api.blockedNetworks()).items);
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  async remove(n: BlockedNetwork): Promise<void> {
    if (!confirm(this.i18n.t('net.confirmRemove', { org: n.org }))) return;
    try {
      await this.api.unblockNetwork(n.asn);
      this.ui.notify('ok', () => this.i18n.t('net.removed', { org: n.org }));
      this.ui.bump();
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}

/** Bots bloqueados por nombre (texto del User-Agent): lista, alta y baja */
@Component({
  selector: 'sg-blocked-bots',
  imports: [TPipe],
  template: `
  <section class="card">
    <h2>{{ 'bb.title' | t }} ({{ items().length }})</h2>
    <p class="muted">{{ 'bb.hint' | t }}</p>
    <div class="row">
      <input class="grow" [placeholder]="'bb.placeholder' | t" [value]="input()" (input)="input.set($any($event.target).value)"
             (keydown.enter)="add()" maxlength="64">
      <button class="danger" [disabled]="input().trim().length < 3" (click)="add()">{{ 'bb.add' | t }}</button>
    </div>
    <div class="scroll"><table>
      <tr><th>{{ 'bb.pattern' | t }}</th><th>{{ 'bb.note' | t }}</th><th>{{ 'bl.created' | t }}</th><th></th></tr>
      @for (b of items(); track b.pattern) {
        <tr><td><code>{{ b.pattern }}</code></td><td>{{ b.note }}</td><td>{{ i18n.date(b.createdAt) }}</td>
          <td class="actions"><button class="small primary" (click)="remove(b.pattern)">{{ 'common.unblock' | t }}</button></td></tr>
      } @empty { <tr><td colspan="4" class="muted">{{ 'common.none' | t }}</td></tr> }
    </table></div>
  </section>
  `,
})
export class BlockedBotsComponent {
  private readonly api = inject(Api);
  private readonly ui = inject(Ui);
  readonly i18n = inject(I18n);
  readonly items = signal<BlockedBot[]>([]);
  readonly input = signal('');

  constructor() {
    effect(() => {
      this.ui.changed();
      void this.load();
    });
  }

  async load(): Promise<void> {
    try {
      this.items.set((await this.api.blockedBots()).items);
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  async add(): Promise<void> {
    const pattern = this.input().trim();
    if (pattern.length < 3) return;
    try {
      const b = await this.api.blockBot({ pattern });
      this.input.set('');
      this.ui.notify('ok', () => this.i18n.t('ev.botBlocked', { pattern: b.pattern }));
      this.ui.bump();
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  async remove(pattern: string): Promise<void> {
    if (!confirm(this.i18n.t('bb.confirmRemove', { pattern }))) return;
    try {
      await this.api.unblockBot(pattern);
      this.ui.notify('ok', () => this.i18n.t('bb.removed', { pattern }));
      this.ui.bump();
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}

/** Qué eventos muestra cada filtro. La acción llega como BLOCK o, en AUDIT, WOULD_BLOCK. */
const EVENT_FILTERS: Record<EventFilter, (e: SecurityEvent) => boolean> = {
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

/** Eventos de seguridad recientes */
@Component({
  selector: 'sg-events',
  imports: [TPipe, IpComponent, BlockButtonsComponent],
  template: `
  <section class="card">
    <div class="row between">
      <h2>{{ 'ev.title' | t }} ({{ shown().length }} / {{ events().length }})</h2>
      <div class="row">
        <select [attr.aria-label]="'ev.filter' | t" (change)="ui.eventFilter.set($any($event.target).value)">
          @for (f of filters; track f) { <option [value]="f" [selected]="ui.eventFilter() === f">{{ ('ev.f.' + f) | t }}</option> }
        </select>
        <input type="search" [placeholder]="'ev.search' | t" [value]="ui.eventQuery()" (input)="ui.eventQuery.set($any($event.target).value)">
      </div>
    </div>
    <div class="scroll"><table>
      <tr><th>{{ 'ev.time' | t }}</th><th>{{ 'ev.action' | t }}</th><th>IP</th><th>{{ 'ev.host' | t }}</th>
        <th>{{ 'ev.request' | t }}</th><th>{{ 'ev.status' | t }}</th><th>{{ 'ev.category' | t }}</th>
        <th class="num">{{ 'ev.delta' | t }}</th><th>{{ 'ev.reason' | t }}</th><th></th></tr>
      @for (e of shown(); track $index) {
        <tr><td class="when">{{ i18n.date(e.timestamp) }}</td>
          <td class="nowrap"><span class="act" [class.bad]="isBlock(e)" [class.warn]="isWarn(e)">{{ e.action }}</span></td>
          <td class="ip"><sg-ip [ip]="e.ip" [country]="e.country ?? ''" /></td>
          <td class="nowrap">{{ e.host }}</td>
          <td class="uri"><code [title]="e.method + ' ' + e.uri">{{ e.method }} {{ e.uri }}</code>
            @if (e.userAgent) { <span class="ua" [title]="e.userAgent">{{ e.userAgent }}</span> }</td>
          <td>{{ e.status ?? '' }}</td><td class="nowrap">{{ e.category }}</td><td class="num">{{ e.scoreDelta }}</td>
          <td class="reason">{{ e.reason }}</td>
          <td class="actions">
            <button class="small" (click)="inspect(e.ip)">{{ 'common.inspect' | t }}</button>
            <sg-block [ip]="e.ip" [ipKey]="e.ipKey ?? ''" [userAgent]="e.userAgent ?? ''" />
          </td></tr>
      } @empty { <tr><td colspan="10" class="muted">{{ 'common.none' | t }}</td></tr> }
    </table></div>
  </section>
  `,
})
export class EventsComponent {
  private readonly api = inject(Api);
  readonly ui = inject(Ui);
  readonly i18n = inject(I18n);
  readonly events = signal<SecurityEvent[]>([]);
  readonly filters: EventFilter[] = ['all', 'log', 'suspicious', 'wouldBlock', 'blocked', 'limited', 'st403', 'st429', 'denied'];

  /** Eventos que pasan el filtro elegido y el texto buscado (IP, ruta, motivo, host o User-Agent). */
  readonly shown = computed(() => {
    const match = EVENT_FILTERS[this.ui.eventFilter()];
    const q = this.ui.eventQuery().trim().toLowerCase();
    return this.events().filter(
      (e) => match(e) && (!q || [e.ip, e.uri, e.reason, e.host, e.category, e.userAgent ?? ''].some((v) => String(v ?? '').toLowerCase().includes(q))),
    );
  });

  constructor() {
    effect(() => {
      this.ui.changed();
      void this.load();
    });
  }

  async load(): Promise<void> {
    try {
      this.events.set(await this.api.events(1000));
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  /** Bloqueada de verdad (BLOCK / RATE_LIMIT) frente a "se habría bloqueado" en AUDIT (WOULD_BLOCK…). */
  isBlock(e: SecurityEvent): boolean {
    return e.action === 'BLOCK' || e.action === 'RATE_LIMIT';
  }
  isWarn(e: SecurityEvent): boolean {
    return e.action === 'WOULD_BLOCK' || e.action === 'WOULD_RATE_LIMIT';
  }

  async inspect(ip: string): Promise<void> {
    try {
      this.ui.inspect.set({ ip, text: (await this.api.explain(ip)).explanation });
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}
