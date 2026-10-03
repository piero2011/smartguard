import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { Api, ApiErr } from './api.service';
import { I18n, Lang, TPipe } from './i18n';
import { Tab, Ui } from './ui';
import { ManageComponent } from './manage.component';
import { SitesComponent } from './sites.component';
import { AllowlistComponent, BansComponent, BlockedBotsComponent, BlockedNetworksComponent, EventsComponent, OverviewComponent } from './tables.component';

@Component({
  selector: 'sg-root',
  imports: [TPipe, ManageComponent, SitesComponent, OverviewComponent, BansComponent, BlockedBotsComponent, BlockedNetworksComponent, AllowlistComponent, EventsComponent],
  template: `
  <header>
    <div class="brand">
      <img class="logo" src="favicon.svg" alt="" width="28" height="28">
      <div><strong>{{ 'app.title' | t }}</strong>
        <span class="muted">{{ 'app.subtitle' | t }}</span></div>
    </div>
    @if (mode(); as m) {
      <span class="pill" [class.audit]="m === 'AUDIT'" [class.enforce]="m === 'ENFORCE'">{{ ('mode.' + m) | t }}</span>
      <button class="small" (click)="toggleMode()">{{ (m === 'AUDIT' ? 'mode.switchToEnforce' : 'mode.switchToAudit') | t }}</button>
    }
    <span class="spacer"></span>
    <label class="lang">{{ 'lang.label' | t }}
      <select (change)="setLang($any($event.target).value)">
        <option value="en" [selected]="i18n.lang() === 'en'">English</option>
        <option value="es" [selected]="i18n.lang() === 'es'">Español</option>
      </select>
    </label>
    <button class="small" [title]="'theme.toggle' | t" (click)="ui.toggleTheme()">{{ ('theme.' + ui.theme()) | t }}</button>
    @if (connected()) {
      <button class="small" (click)="refresh()">{{ 'common.refresh' | t }}</button>
      <button class="small" (click)="logout()">{{ 'auth.logout' | t }}</button>
    }
  </header>

  @if (!connected()) {
    <main class="narrow">
      <section class="card">
        <h2>{{ 'auth.token' | t }}</h2>
        <p class="muted">{{ 'auth.hint' | t }}</p>
        <div class="row">
          <input class="grow" type="password" [value]="tokenInput()" (input)="tokenInput.set($any($event.target).value)"
                 (keydown.enter)="connect()" autocomplete="off">
          <button class="primary" (click)="connect()">{{ 'auth.connect' | t }}</button>
        </div>
        @if (authError()) { <p class="msg error">{{ authError() }}</p> }
      </section>
    </main>
  } @else {
    <nav>
      @for (t of tabs; track t) {
        <button [class.active]="tab() === t" (click)="tab.set(t)">{{ ('tab.' + t) | t }}</button>
      }
      @if (lastUpdate()) { <span class="muted small-text">{{ 'common.updated' | t: { time: lastUpdate() } }}</span> }
    </nav>
    <main>
      @switch (tab()) {
        @case ('overview') { <sg-overview /> }
        @case ('manage') { <sg-manage /> <sg-sites /> }
        @case ('blocked') { <sg-bans /> <sg-blocked-networks /> <sg-blocked-bots /> }
        @case ('allowlist') { <sg-allowlist /> }
        @case ('events') { <sg-events /> }
      }
    </main>
  }

  <div class="toasts">
    @for (n of ui.notices(); track n.id) {
      <div class="toast" [class]="n.kind" (click)="ui.dismiss(n.id)">{{ n.text() }}</div>
    }
  </div>

  @if (ui.inspect(); as ins) {
    <div class="modal-bg" (click)="ui.inspect.set(null)">
      <div class="modal" (click)="$event.stopPropagation()">
        <div class="row between"><h2>{{ 'inspect.title' | t: { ip: ins.ip } }}</h2>
          <button class="small" (click)="ui.inspect.set(null)">{{ 'inspect.close' | t }}</button></div>
        <pre>{{ ins.text }}</pre>
      </div>
    </div>
  }
  `,
})
export class AppComponent implements OnInit, OnDestroy {
  readonly i18n = inject(I18n);
  readonly ui = inject(Ui);
  private readonly api = inject(Api);

  readonly tabs: Tab[] = ['overview', 'manage', 'blocked', 'allowlist', 'events'];
  readonly tab = this.ui.tab;
  readonly connected = signal(false);
  readonly tokenInput = signal('');
  readonly authError = signal('');
  readonly mode = signal<'AUDIT' | 'ENFORCE' | null>(null);
  readonly lastUpdate = signal('');
  private timer: ReturnType<typeof setInterval> | null = null;

  async ngOnInit(): Promise<void> {
    if (this.api.token()) await this.verify();
    this.timer = setInterval(() => {
      // con la pestaña del navegador en segundo plano no se consulta nada
      if (this.connected() && this.tab() !== 'manage' && !document.hidden) this.refresh();
    }, 30_000);
  }

  ngOnDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  setLang(l: Lang): void {
    this.i18n.set(l);
  }

  async connect(): Promise<void> {
    this.api.setToken(this.tokenInput());
    await this.verify();
  }

  private async verify(): Promise<void> {
    try {
      const m = await this.api.mode();
      this.mode.set(m.audit ? 'AUDIT' : 'ENFORCE');
      this.connected.set(true);
      this.authError.set('');
      this.lastUpdate.set(this.i18n.time(Date.now()));
    } catch (e) {
      const err = e as ApiErr;
      this.connected.set(false);
      this.authError.set(err.status === 401 ? this.i18n.t('auth.invalid') : this.api.describe(err));
    }
  }

  refresh(): void {
    this.ui.bump();
    void this.api.mode().then((m) => this.mode.set(m.audit ? 'AUDIT' : 'ENFORCE')).catch(() => undefined);
    this.lastUpdate.set(this.i18n.time(Date.now()));
  }

  async toggleMode(): Promise<void> {
    const toAudit = this.mode() === 'ENFORCE';
    if (!confirm(this.i18n.t(toAudit ? 'mode.confirmAudit' : 'mode.confirmEnforce'))) return;
    try {
      const m = await this.api.setMode(toAudit);
      this.mode.set(m.audit ? 'AUDIT' : 'ENFORCE');
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  logout(): void {
    this.api.setToken('');
    this.connected.set(false);
    this.tokenInput.set('');
  }
}
