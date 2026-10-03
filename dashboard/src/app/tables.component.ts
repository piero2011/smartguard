import { Component, OnDestroy, computed, effect, inject, signal, untracked } from '@angular/core';
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
      for (const e of await this.api.events(300)) {
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

/** Eventos por página y máximo de peticiones encadenadas para llenar una (cada una revisa un tramo acotado). */
const EVENTS_PAGE_SIZE = 50;
const EVENTS_MAX_ROUNDS = 8;

/** Eventos de seguridad: una página cada vez; filtros, búsqueda y fechas los resuelve el servidor. */
@Component({
  selector: 'sg-events',
  imports: [TPipe, IpComponent, BlockButtonsComponent],
  template: `
  <section class="card">
    <div class="row between">
      <h2>{{ 'ev.title' | t }}</h2>
      <div class="row">
        <select [attr.aria-label]="'ev.filter' | t" (change)="ui.eventFilter.set($any($event.target).value)">
          @for (f of filters; track f) { <option [value]="f" [selected]="ui.eventFilter() === f">{{ ('ev.f.' + f) | t }}</option> }
        </select>
        <input type="search" [placeholder]="'ev.search' | t" [value]="ui.eventQuery()" (input)="ui.eventQuery.set($any($event.target).value)">
      </div>
    </div>
    <div class="row">
      <label>{{ 'ev.from' | t }}
        <input type="datetime-local" [value]="ui.eventFrom()" (change)="ui.eventFrom.set($any($event.target).value)"></label>
      <label>{{ 'ev.to' | t }}
        <input type="datetime-local" [value]="ui.eventTo()" (change)="ui.eventTo.set($any($event.target).value)"></label>
      <button class="small" (click)="today()">{{ 'ev.today' | t }}</button>
      @if (ui.eventFrom() || ui.eventTo()) { <button class="small" (click)="clearDates()">{{ 'ev.clearDates' | t }}</button> }
    </div>
    <div class="scroll"><table>
      <tr><th>{{ 'ev.time' | t }}</th><th>{{ 'ev.action' | t }}</th><th>IP</th><th>{{ 'ev.host' | t }}</th>
        <th>{{ 'ev.request' | t }}</th><th>{{ 'ev.status' | t }}</th><th>{{ 'ev.category' | t }}</th>
        <th class="num">{{ 'ev.delta' | t }}</th><th>{{ 'ev.reason' | t }}</th><th></th></tr>
      @for (e of events(); track $index) {
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
      } @empty { <tr><td colspan="10" class="muted">{{ (loading() ? 'ev.loading' : 'common.none') | t }}</td></tr> }
    </table></div>
    <div class="row between">
      <span class="muted">{{ 'ev.page' | t: { page: page(), count: events().length } }}@if (loading()) { · {{ 'ev.loading' | t }} }</span>
      <div class="row">
        <button class="small" [disabled]="page() === 1 || loading()" (click)="first()">{{ 'ev.first' | t }}</button>
        <button class="small" [disabled]="page() === 1 || loading()" (click)="prev()">{{ 'ev.prev' | t }}</button>
        <button class="small" [disabled]="!next() || loading()" (click)="forward()">{{ 'ev.next' | t }}</button>
      </div>
    </div>
  </section>
  `,
})
export class EventsComponent implements OnDestroy {
  private readonly api = inject(Api);
  readonly ui = inject(Ui);
  readonly i18n = inject(I18n);
  readonly events = signal<SecurityEvent[]>([]);
  readonly filters: EventFilter[] = ['all', 'log', 'suspicious', 'wouldBlock', 'blocked', 'limited', 'st403', 'st429', 'denied'];
  readonly loading = signal(false);
  /** cursor con el que se pidió cada página ya visitada ('' = la primera, los eventos más recientes) */
  private readonly cursors = signal<string[]>(['']);
  /** cursor de la página siguiente (null = no hay más) */
  readonly next = signal<string | null>(null);
  readonly page = computed(() => this.cursors().length);
  /** Texto buscado, con retardo: no se consulta al servidor en cada pulsación. */
  private readonly query = signal(this.ui.eventQuery().trim());
  private typing: ReturnType<typeof setTimeout> | null = null;
  private filterKey = '';
  private loadSeq = 0;

  constructor() {
    effect(() => {
      const q = this.ui.eventQuery().trim();
      if (this.typing) clearTimeout(this.typing);
      this.typing = setTimeout(() => this.query.set(q), 350);
    });
    effect(() => {
      this.ui.changed();
      const key = JSON.stringify([this.ui.eventFilter(), this.query(), this.ui.eventFrom(), this.ui.eventTo()]);
      untracked(() => {
        if (key !== this.filterKey) {
          this.filterKey = key;
          this.cursors.set(['']);
          void this.load();
        } else if (this.page() === 1) {
          // el refresco periódico solo trae eventos nuevos: las páginas anteriores no cambian
          void this.load();
        }
      });
    });
  }

  ngOnDestroy(): void {
    if (this.typing) clearTimeout(this.typing);
  }

  async load(): Promise<void> {
    const seq = ++this.loadSeq;
    const ms = (v: string) => (v && !Number.isNaN(new Date(v).getTime()) ? new Date(v).getTime() : undefined);
    const base = { kind: this.ui.eventFilter(), q: this.query(), from: ms(this.ui.eventFrom()), to: ms(this.ui.eventTo()) };
    this.loading.set(true);
    try {
      const items: SecurityEvent[] = [];
      let cursor: string | null = this.cursors()[this.cursors().length - 1] || null;
      // Con filtros el servidor revisa un tramo acotado por petición: se encadenan hasta llenar la página.
      for (let round = 0; round < EVENTS_MAX_ROUNDS; round++) {
        const r = await this.api.eventsPage({ ...base, limit: EVENTS_PAGE_SIZE - items.length, cursor: cursor ?? undefined });
        // una respuesta antigua no debe pisar a la de una búsqueda posterior
        if (seq !== this.loadSeq) return;
        items.push(...r.items);
        cursor = r.next;
        if (!cursor || items.length >= EVENTS_PAGE_SIZE) break;
      }
      this.events.set(items);
      this.next.set(cursor);
    } catch (e) {
      if (seq === this.loadSeq) this.ui.notify('error', () => this.api.describe(e as ApiErr));
    } finally {
      if (seq === this.loadSeq) this.loading.set(false);
    }
  }

  first(): void {
    this.cursors.set(['']);
    void this.load();
  }

  prev(): void {
    this.cursors.update((c) => (c.length > 1 ? c.slice(0, -1) : c));
    void this.load();
  }

  forward(): void {
    const n = this.next();
    if (!n) return;
    this.cursors.update((c) => [...c, n]);
    void this.load();
  }

  /** Desde las 00:00 de hoy (hora del navegador) hasta ahora. */
  today(): void {
    const d = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    this.ui.eventFrom.set(`${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T00:00`);
    this.ui.eventTo.set('');
  }

  clearDates(): void {
    this.ui.eventFrom.set('');
    this.ui.eventTo.set('');
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
