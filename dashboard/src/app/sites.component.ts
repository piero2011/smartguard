import { Component, computed, inject, signal } from '@angular/core';
import { Api, ApiErr, NginxSites } from './api.service';
import { I18n, TPipe } from './i18n';
import { Ui } from './ui';
import { PagerComponent, pageCount, pageOf } from './pager.component';

/** Lo que hay que pegar en el vhost de un sitio para protegerlo (ver docs/02-PROCEDIMIENTOS.md 13.5). */
const SNIPPET = `server {
    ...
    include /etc/nginx/smartguard/server.conf;   # al principio del server
    include /etc/nginx/smartguard/auth.conf;
    ...
    location ~ \\.php$ {
        include /etc/nginx/smartguard/auth-php.conf;   # en CADA location con fastcgi_pass
        ...
    }
}`;

/** Sitios que Nginx tiene configurados, cuáles pasan por SmartGuard y cómo añadir otro. */
@Component({
  selector: 'sg-sites',
  imports: [TPipe, PagerComponent],
  template: `
  <section class="card">
    <div class="row between">
      <h2>{{ 'st.title' | t }} @if (data(); as d) { ({{ protectedCount() }} / {{ d.items.length }}) }</h2>
      <div class="row">
        <input type="search" [placeholder]="'st.search' | t" [value]="query()" (input)="query.set($any($event.target).value); wanted.set(1)">
        <button class="small" (click)="load()">{{ 'common.refresh' | t }}</button>
      </div>
    </div>
    <p class="muted sub">{{ 'st.hint' | t }}</p>
    @if (data(); as d) {
      @if (!d.readable) { <p class="msg warn">{{ 'st.unreadable' | t: { dirs: d.dirs.join(', ') } }}</p> }
      <div class="scroll"><table>
        <tr><th></th><th>{{ 'st.site' | t }}</th><th>{{ 'st.kind' | t }}</th><th>{{ 'st.status' | t }}</th>
          <th>{{ 'st.rules' | t }}</th><th>{{ 'st.decision' | t }}</th><th>{{ 'st.file' | t }}</th></tr>
        @for (s of shown(); track s.file) {
          <tr>
            <td><input type="checkbox" [attr.aria-label]="'st.pick' | t: { site: s.names[0] }" [checked]="picked().has(s.file)"
                       (change)="toggle(s.file, $any($event.target).checked)"></td>
            <td>@for (n of s.names; track n) { <code class="name">{{ n }}</code> }</td>
            <td class="nowrap">{{ ('st.kind.' + s.kind) | t }}</td>
            <td class="nowrap"><span class="pill" [class.enforce]="s.status === 'full'" [class.audit]="s.status === 'partial'" [class.off]="s.status === 'none'">{{ ('st.s.' + s.status) | t }}</span>
              @if (s.exempt) { <span class="tag cf" [title]="'st.exemptHint' | t">{{ 'st.exempt' | t }}</span> }</td>
            <td>{{ (s.rules ? 'common.yes' : 'common.no') | t }}</td>
            <td>{{ (s.decision ? 'common.yes' : 'common.no') | t }}</td>
            <td class="muted"><code>{{ s.file }}</code></td>
          </tr>
        } @empty { <tr><td colspan="7" class="muted">{{ (query() ? 'st.noMatch' : 'common.none') | t }}</td></tr> }
      </table></div>
      <sg-pager [page]="page()" [total]="filtered().length" (go)="wanted.set($event)" />
      <div class="status">
        @if (picked().size === 0) {
          <p class="muted">{{ 'st.pickHint' | t }}</p>
        } @else {
          <p>{{ 'st.cmdProtect' | t: { count: picked().size } }}</p>
          <div class="row"><pre class="snippet grow">{{ command('protect') }}</pre>
            <button (click)="copy(command('protect'))">{{ 'st.copy' | t }}</button></div>
          <p class="muted">{{ 'st.cmdHint' | t }}</p>
          <p class="muted">{{ 'st.cmdUnprotect' | t }} <code>{{ command('unprotect') }}</code></p>
          <button class="small" (click)="picked.set(emptySet)">{{ 'st.clear' | t }}</button>
        }
      </div>
    } @else { <p class="muted">{{ 'common.loading' | t }}</p> }
  </section>

  <section class="card">
    <h2>{{ 'st.addTitle' | t }}</h2>
    <p class="muted sub">{{ 'st.addManual' | t }}</p>
    <ol class="steps">
      <li>{{ 'st.add1' | t }}</li>
      <li>{{ 'st.add2' | t }}</li>
      <li>{{ 'st.add3' | t }}</li>
      <li>{{ 'st.add4' | t }}</li>
    </ol>
    <pre class="snippet">{{ snippet }}</pre>
    <p class="msg warn">{{ 'st.addWarn' | t }}</p>
    <p class="muted">{{ 'st.addApps' | t }}</p>
  </section>
  `,
})
export class SitesComponent {
  private readonly api = inject(Api);
  private readonly ui = inject(Ui);
  private readonly i18n = inject(I18n);
  readonly data = signal<NginxSites | null>(null);
  readonly snippet = SNIPPET;
  readonly wanted = signal(1);
  /** texto del buscador: dominio, archivo del vhost, tipo o estado */
  readonly query = signal('');
  readonly filtered = computed(() => {
    const q = this.query().trim().toLowerCase();
    const items = this.data()?.items ?? [];
    if (!q) return items;
    return items.filter((s) =>
      [...s.names, s.file, this.i18n.t('st.kind.' + s.kind), this.i18n.t('st.s.' + s.status), s.exempt ? this.i18n.t('st.exempt') : ''].some((v) => v.toLowerCase().includes(q)),
    );
  });
  readonly page = computed(() => Math.min(this.wanted(), pageCount(this.filtered().length)));
  readonly shown = computed(() => pageOf(this.filtered(), this.page()));
  /** archivos de vhost marcados para proteger */
  readonly picked = signal<ReadonlySet<string>>(new Set());
  readonly emptySet: ReadonlySet<string> = new Set();
  readonly protectedCount = computed(() => (this.data()?.items ?? []).filter((s) => s.status !== 'none').length);

  constructor() {
    void this.load();
  }

  toggle(file: string, on: boolean): void {
    const next = new Set(this.picked());
    if (on) next.add(file);
    else next.delete(file);
    this.picked.set(next);
  }

  /** Comando para el servidor con los sitios marcados (por el nombre de su archivo de vhost). */
  command(action: 'protect' | 'unprotect'): string {
    const names = (this.data()?.items ?? []).filter((s) => this.picked().has(s.file)).map((s) => s.file.replace(/\.conf$/, ''));
    return `sudo smartguard ${action} ${names.join(' ')}`;
  }

  async copy(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.ui.notify('ok', () => this.i18n.t('st.copied'));
    } catch {
      this.ui.notify('warn', () => this.i18n.t('st.copyFailed'));
    }
  }

  async load(): Promise<void> {
    try {
      this.data.set(await this.api.sites());
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}
