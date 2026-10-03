import { Component, WritableSignal, inject, signal } from '@angular/core';
import { AllowMatch, Api, ApiErr, ClientList, LookupResult, PERMANENT, isPermanent } from './api.service';
import { I18n, TPipe } from './i18n';
import { Text, Ui } from './ui';

type Msg = { kind: 'ok' | 'error' | 'warn'; text: Text } | null;

/**
 * Gestión de IPs y sitios:
 *  - Consultar dónde está un valor (lista blanca, bloqueo) mientras se escribe.
 *  - Permitir cliente (IP / CIDR / dominio / *.dominio).
 *  - Permitir sitio o subdominio destino (dominio / *.dominio / URL).
 *  - Bloquear IP · Desbloquear IP.
 * Si el valor ya está en una lista, se indica en cuál (lo valida también el backend: 409).
 */
@Component({
  selector: 'sg-manage',
  imports: [TPipe],
  template: `
  <section class="card">
    <h2>{{ 'mg.check.title' | t }}</h2>
    <p class="muted">{{ 'mg.check.help' | t }}</p>
    <div class="row">
      <input class="grow" [value]="query()" (input)="onQuery($any($event.target).value)" (keydown.enter)="check()"
             [placeholder]="'mg.check.placeholder' | t" autocomplete="off" spellcheck="false">
      <button (click)="check()" [disabled]="checking()">{{ 'mg.check.button' | t }}</button>
    </div>

    @if (lookupError()) { <p class="msg error">{{ lookupError() }}</p> }

    @if (result(); as r) {
      <div class="status">
        <div><code>{{ r.isIp ? ipOf(r) : r.normalized }}</code>@if (r.key && r.key !== ipOf(r)) { <span class="muted"> → {{ r.key }}</span> }</div>

        @if (r.isCloudflare) { <p class="msg warn">{{ 'mg.status.cloudflare' | t }}</p> }

        @if (r.allowlisted) {
          <p class="msg ok">{{ 'mg.status.allowlisted' | t: { value: r.normalized } }}</p>
          <ul class="matches">
            @for (m of r.allowlist; track $index) { <li>{{ matchText(m) }}</li> }
          </ul>
        }
        @if (r.banned && r.ban) {
          <p class="msg error">{{ 'mg.status.blocked' | t: { value: r.normalized, until: untilText(r.ban.expiresAt) } }}
            <span class="muted">({{ r.ban.reason }})</span></p>
        }
        @if (!r.banned && r.auditBan) {
          <p class="msg warn">{{ 'mg.status.auditBlocked' | t: { until: untilText(r.auditBan.expiresAt) } }}</p>
        }
        @if (r.fingerprintBans > 0) { <p class="msg warn">{{ 'mg.status.fpBans' | t: { count: r.fingerprintBans } }}</p> }
        @if (!r.allowlisted && !r.banned && !r.auditBan && !r.fingerprintBans) {
          <p class="msg neutral">{{ 'mg.status.notListed' | t: { value: r.normalized } }}</p>
        }
        @if (r.score !== null) { <p class="muted">{{ 'mg.status.score' | t: { score: r.score } }}</p> }

        <div class="row">
          @if (r.isIp && (r.banned || r.fingerprintBans > 0)) {
            <button class="primary" (click)="unblockIp.set(ipOf(r)); doUnblock()">{{ 'common.unblock' | t }}</button>
          }
          @if (r.isIp && !r.banned && !r.allowlisted && !r.isCloudflare) {
            <button class="danger" (click)="blockIp.set(ipOf(r))">{{ 'mg.block.submit' | t }} …</button>
          }
          @if (!r.allowlisted) {
            <button (click)="allowValue.set(r.normalized)">{{ 'mg.allow.submit' | t }} …</button>
            @if (!r.isIp && r.kind !== 'cidr') { <button (click)="hostValue.set(r.normalized)">{{ 'mg.host.submit' | t }} …</button> }
          }
          @if (r.isIp) { <button (click)="inspect(ipOf(r))">{{ 'common.inspect' | t }}</button> }
        </div>
      </div>
    }
  </section>

  <div class="grid2">
    <section class="card">
      <h2>{{ 'mg.allow.title' | t }}</h2>
      <p class="muted">{{ 'mg.allow.help' | t }}</p>
      <label>{{ 'mg.allow.value' | t }}
        <input [value]="allowValue()" (input)="allowValue.set($any($event.target).value)" autocomplete="off" spellcheck="false"></label>
      <div class="row">
        <label class="grow">{{ 'mg.allow.list' | t }}
          <select (change)="allowList.set($any($event.target).value)">
            @for (l of lists; track l) { <option [value]="l" [selected]="l === allowList()">{{ ('list.' + l) | t }}</option> }
          </select></label>
        <label>{{ 'mg.allow.ttl' | t }}
          <select (change)="allowTtl.set($any($event.target).value)">
            <option value="" [selected]="allowTtl() === ''">{{ 'ttl.never' | t }}</option>
            @for (d of durations; track d) { <option [value]="d" [selected]="d === allowTtl()">{{ ('dur.' + d) | t }}</option> }
          </select></label>
      </div>
      <label>{{ 'mg.allow.note' | t }}
        <input [value]="allowNote()" (input)="allowNote.set($any($event.target).value)" maxlength="200"></label>
      <button class="primary" (click)="doAllow()" [disabled]="busy() || !allowValue().trim()">{{ 'mg.allow.submit' | t }}</button>
      @if (allowMsg(); as m) { <p class="msg" [class]="m.kind">{{ m.text() }}</p> }
    </section>

    <section class="card">
      <h2>{{ 'mg.host.title' | t }}</h2>
      <p class="muted">{{ 'mg.host.help' | t }}</p>
      <label>{{ 'mg.host.value' | t }}
        <input [value]="hostValue()" (input)="hostValue.set($any($event.target).value)" autocomplete="off" spellcheck="false"></label>
      <label>{{ 'mg.allow.note' | t }}
        <input [value]="hostNote()" (input)="hostNote.set($any($event.target).value)" maxlength="200"></label>
      <button class="primary" (click)="doHost()" [disabled]="busy() || !hostValue().trim()">{{ 'mg.host.submit' | t }}</button>
      @if (hostMsg(); as m) { <p class="msg" [class]="m.kind">{{ m.text() }}</p> }
    </section>

    <section class="card">
      <h2>{{ 'mg.block.title' | t }}</h2>
      <p class="muted">{{ 'mg.block.help' | t }}</p>
      <label>{{ 'mg.block.ip' | t }}
        <input [value]="blockIp()" (input)="blockIp.set($any($event.target).value)" autocomplete="off" spellcheck="false"></label>
      <div class="row">
        <label>{{ 'mg.block.duration' | t }}
          <select (change)="blockDuration.set($any($event.target).value)">
            @for (d of blockDurations; track d) { <option [value]="d" [selected]="d === blockDuration()">{{ ('dur.' + d) | t }}</option> }
          </select></label>
        <label class="grow">{{ 'mg.block.reason' | t }}
          <input [value]="blockReason()" (input)="blockReason.set($any($event.target).value)" maxlength="200"></label>
      </div>
      <button class="danger" (click)="doBlock()" [disabled]="busy() || !blockIp().trim()">{{ 'mg.block.submit' | t }}</button>
      @if (blockMsg(); as m) { <p class="msg" [class]="m.kind">{{ m.text() }}</p> }
    </section>

    <section class="card">
      <h2>{{ 'mg.unblock.title' | t }}</h2>
      <p class="muted">{{ 'mg.unblock.help' | t }}</p>
      <label>{{ 'mg.block.ip' | t }}
        <input [value]="unblockIp()" (input)="unblockIp.set($any($event.target).value)" autocomplete="off" spellcheck="false"></label>
      <label class="check"><input type="checkbox" [checked]="keepScore()" (change)="keepScore.set($any($event.target).checked)">
        {{ 'mg.unblock.keepScore' | t }}</label>
      <button class="primary" (click)="doUnblock()" [disabled]="busy() || !unblockIp().trim()">{{ 'mg.unblock.submit' | t }}</button>
      @if (unblockMsg(); as m) { <p class="msg" [class]="m.kind">{{ m.text() }}</p> }
    </section>
  </div>
  `,
})
export class ManageComponent {
  private readonly api = inject(Api);
  private readonly i18n = inject(I18n);
  private readonly ui = inject(Ui);

  readonly lists: ClientList[] = ['ADMIN_ALLOWLIST', 'SERVICE_ALLOWLIST', 'TRUSTED_NETWORK'];
  readonly durations = ['15m', '1h', '6h', '24h', '7d', '30d', '365d'];

  readonly query = signal('');
  readonly result = signal<LookupResult | null>(null);
  readonly lookupError = signal('');
  readonly checking = signal(false);
  readonly busy = signal(false);

  readonly allowValue = signal('');
  readonly allowList = signal<ClientList>('ADMIN_ALLOWLIST');
  readonly allowNote = signal('');
  readonly allowTtl = signal('');
  readonly allowMsg = signal<Msg>(null);

  readonly hostValue = signal('');
  readonly hostNote = signal('');
  readonly hostMsg = signal<Msg>(null);

  readonly blockIp = signal('');
  /** Por defecto, un bloqueo manual dura hasta que se desbloquea a mano. */
  readonly blockDurations = [PERMANENT, ...this.durations];
  readonly blockDuration = signal(PERMANENT);
  readonly blockReason = signal('');
  readonly blockMsg = signal<Msg>(null);

  readonly unblockIp = signal('');
  readonly keepScore = signal(false);
  readonly unblockMsg = signal<Msg>(null);

  private debounce: ReturnType<typeof setTimeout> | null = null;

  onQuery(v: string): void {
    this.query.set(v);
    if (this.debounce) clearTimeout(this.debounce);
    if (v.trim().length < 3) {
      this.result.set(null);
      this.lookupError.set('');
      return;
    }
    this.debounce = setTimeout(() => void this.check(), 450);
  }

  async check(value = this.query()): Promise<void> {
    const v = value.trim();
    if (!v) return;
    this.checking.set(true);
    try {
      this.result.set(await this.api.lookup(v));
      this.lookupError.set('');
    } catch (e) {
      this.result.set(null);
      this.lookupError.set(this.api.describe(e as ApiErr));
    } finally {
      this.checking.set(false);
    }
  }

  ipOf(r: LookupResult): string {
    return r.normalized.split('/')[0] ?? r.normalized;
  }

  untilText(ms: number): string {
    return this.i18n.t('common.until', { date: this.i18n.date(ms) });
  }

  matchText(m: AllowMatch): string {
    return this.i18n.t('mg.match', {
      list: this.i18n.t('list.' + m.list),
      source: this.i18n.t('source.' + m.source) + (m.note ? ` “${m.note}”` : ''),
      how: this.i18n.t('how.' + m.matchedBy, { value: m.value }),
      detail: m.detail ? ` (${m.detail})` : '',
    });
  }

  async inspect(ip: string): Promise<void> {
    try {
      const r = await this.api.explain(ip);
      this.ui.inspect.set({ ip, text: r.explanation });
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  /** Ejecuta una acción, muestra el resultado en su tarjeta y refresca la consulta y las tablas. */
  private async run(target: WritableSignal<Msg>, fn: () => Promise<Text>, recheck: string): Promise<void> {
    this.busy.set(true);
    target.set(null);
    try {
      const text = await fn();
      target.set({ kind: 'ok', text });
      this.ui.notify('ok', text);
      this.ui.bump();
    } catch (e) {
      const err = e as ApiErr;
      target.set({ kind: err.status === 409 ? 'warn' : 'error', text: () => this.api.describe(err) });
    } finally {
      this.busy.set(false);
    }
    if (recheck) {
      this.query.set(recheck);
      await this.check(recheck);
    }
  }

  doAllow(): Promise<void> {
    const value = this.allowValue().trim();
    return this.run(
      this.allowMsg,
      async () => {
        const r = await this.api.allow({
          value,
          type: this.allowList(),
          target: 'client',
          note: this.allowNote().trim() || 'dashboard',
          ttl: this.allowTtl() || undefined,
        });
        return () => this.i18n.t('mg.allow.done', { value: r.entry.value, list: this.i18n.t('list.' + r.entry.type) });
      },
      value,
    );
  }

  doHost(): Promise<void> {
    const value = this.hostValue().trim();
    return this.run(
      this.hostMsg,
      async () => {
        const r = await this.api.allow({ value, type: 'SERVICE_ALLOWLIST', target: 'host', note: this.hostNote().trim() || 'dashboard' });
        return () => this.i18n.t('mg.host.done', { value: r.entry.value });
      },
      value,
    );
  }

  doBlock(): Promise<void> {
    const ip = this.blockIp().trim();
    return this.run(
      this.blockMsg,
      async () => {
        const r = await this.api.ban({ ip, duration: this.blockDuration(), reason: this.blockReason().trim() || 'dashboard' });
        return () => (isPermanent(r.expiresAt) ? this.i18n.t('ev.ipBlocked', { ip: r.key }) : this.i18n.t('mg.block.done', { ip: r.key, until: this.i18n.date(r.expiresAt) }));
      },
      ip,
    );
  }

  doUnblock(): Promise<void> {
    const ip = this.unblockIp().trim();
    return this.run(
      this.unblockMsg,
      async () => {
        const r = await this.api.unban(ip, this.keepScore());
        return r.removed
          ? () => this.i18n.t('mg.unblock.done', { ip, fp: r.fingerprintBans })
          : () => this.i18n.t('mg.unblock.notBlocked', { ip, reset: this.i18n.t(r.reset ? 'common.yes' : 'common.no') });
      },
      ip,
    );
  }
}
