import { Component, computed, inject, signal } from '@angular/core';
import { Api, ApiErr, NginxSites } from './api.service';
import { TPipe } from './i18n';
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
      <button class="small" (click)="load()">{{ 'common.refresh' | t }}</button>
    </div>
    <p class="muted sub">{{ 'st.hint' | t }}</p>
    @if (data(); as d) {
      @if (!d.readable) { <p class="msg warn">{{ 'st.unreadable' | t: { dirs: d.dirs.join(', ') } }}</p> }
      <div class="scroll"><table>
        <tr><th>{{ 'st.site' | t }}</th><th>{{ 'st.kind' | t }}</th><th>{{ 'st.status' | t }}</th>
          <th>{{ 'st.rules' | t }}</th><th>{{ 'st.decision' | t }}</th><th>{{ 'st.file' | t }}</th></tr>
        @for (s of shown(); track s.file) {
          <tr>
            <td>@for (n of s.names; track n) { <code class="name">{{ n }}</code> }</td>
            <td class="nowrap">{{ ('st.kind.' + s.kind) | t }}</td>
            <td class="nowrap"><span class="pill" [class.enforce]="s.status === 'full'" [class.audit]="s.status === 'partial'" [class.off]="s.status === 'none'">{{ ('st.s.' + s.status) | t }}</span>
              @if (s.exempt) { <span class="tag cf" [title]="'st.exemptHint' | t">{{ 'st.exempt' | t }}</span> }</td>
            <td>{{ (s.rules ? 'common.yes' : 'common.no') | t }}</td>
            <td>{{ (s.decision ? 'common.yes' : 'common.no') | t }}</td>
            <td class="muted"><code>{{ s.file }}</code></td>
          </tr>
        } @empty { <tr><td colspan="6" class="muted">{{ 'common.none' | t }}</td></tr> }
      </table></div>
      <sg-pager [page]="page()" [total]="d.items.length" (go)="wanted.set($event)" />
    } @else { <p class="muted">{{ 'common.loading' | t }}</p> }
  </section>

  <section class="card">
    <h2>{{ 'st.addTitle' | t }}</h2>
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
  readonly data = signal<NginxSites | null>(null);
  readonly snippet = SNIPPET;
  readonly wanted = signal(1);
  readonly page = computed(() => Math.min(this.wanted(), pageCount(this.data()?.items.length ?? 0)));
  readonly shown = computed(() => pageOf(this.data()?.items ?? [], this.page()));
  readonly protectedCount = computed(() => (this.data()?.items ?? []).filter((s) => s.status !== 'none').length);

  constructor() {
    void this.load();
  }

  async load(): Promise<void> {
    try {
      this.data.set(await this.api.sites());
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}
