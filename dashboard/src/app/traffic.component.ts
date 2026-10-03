import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { Api, ApiErr, RecentTraffic } from './api.service';
import { I18n, TPipe } from './i18n';
import { Ui } from './ui';
import { IpComponent } from './ipinfo';
import { BlockButtonsComponent } from './block.component';
import { PagerComponent, pageCount, pageOf } from './pager.component';

/**
 * Tráfico reciente: lo que SmartGuard está evaluando ahora mismo, también las visitas normales
 * (que no generan evento de seguridad). Respeta el sitio elegido en la cabecera.
 */
@Component({
  selector: 'sg-traffic',
  imports: [TPipe, IpComponent, BlockButtonsComponent, PagerComponent],
  template: `
  <section class="card">
    <div class="row between">
      <h2>{{ 'tr.ipsTitle' | t }} ({{ ips().length }})</h2>
      <input type="search" [placeholder]="'tr.search' | t" [value]="query()" (input)="query.set($any($event.target).value); page.set(1)">
    </div>
    <p class="muted sub">{{ 'tr.ipsHint' | t }}</p>
    <div class="scroll"><table>
      <tr><th>IP</th><th class="num">{{ 'tr.requests' | t }}</th><th>{{ 'tr.lastPath' | t }}</th><th>{{ 'tr.lastSeen' | t }}</th><th></th></tr>
      @for (i of ips(); track i.ipKey) {
        <tr>
          <td class="ip"><sg-ip [ip]="i.ip" [country]="i.country ?? ''" /></td>
          <td class="num">{{ i.requests }}@if (i.blocked) { <span class="act bad"> · {{ 'tr.blocked' | t: { n: i.blocked } }}</span> }</td>
          <td class="uri"><code [title]="i.lastPath">{{ i.lastPath }}</code><span class="ua" [title]="i.userAgent">{{ i.userAgent }}</span></td>
          <td class="when">{{ i18n.time(i.lastSeen) }}</td>
          <td class="actions">
            <button class="small" (click)="inspect(i.ip)">{{ 'common.inspect' | t }}</button>
            <sg-block [ip]="i.ip" [ipKey]="i.ipKey" [userAgent]="i.userAgent" />
          </td>
        </tr>
      } @empty { <tr><td colspan="5" class="muted">{{ (query() ? 'tr.noMatch' : 'tr.noIps') | t }}</td></tr> }
    </table></div>
  </section>

  <section class="card">
    <h2>{{ 'tr.reqTitle' | t }} ({{ items().length }})</h2>
    <p class="muted sub">{{ 'tr.reqHint' | t: { stored: data()?.stored ?? 0 } }}</p>
    <div class="scroll"><table>
      <tr><th>{{ 'ev.time' | t }}</th><th>{{ 'tr.decision' | t }}</th><th>IP</th><th>{{ 'ev.host' | t }}</th><th>{{ 'ev.request' | t }}</th></tr>
      @for (r of shown(); track $index) {
        <tr>
          <td class="when">{{ i18n.date(r.t) }}</td>
          <td class="nowrap"><span class="act" [class.bad]="r.action === 'BLOCK' || r.action === 'RATE_LIMIT'" [class.warn]="r.action.startsWith('WOULD_')">{{ r.action }}</span></td>
          <td class="ip"><sg-ip [ip]="r.ip" [country]="r.country ?? ''" /></td>
          <td class="nowrap">{{ r.host }}</td>
          <td class="uri"><code [title]="r.method + ' ' + r.path">{{ r.method }} {{ r.path }}</code>
            @if (r.userAgent) { <span class="ua" [title]="r.userAgent">{{ r.userAgent }}</span> }</td>
        </tr>
      } @empty { <tr><td colspan="5" class="muted">{{ (query() ? 'tr.noMatch' : 'tr.noReq') | t }}</td></tr> }
    </table></div>
    <sg-pager [page]="pageSafe()" [total]="items().length" (go)="page.set($event)" />
  </section>
  `,
})
export class TrafficComponent {
  private readonly api = inject(Api);
  readonly ui = inject(Ui);
  readonly i18n = inject(I18n);
  readonly data = signal<RecentTraffic | null>(null);
  readonly query = signal('');
  readonly page = signal(1);
  private loadSeq = 0;

  private match(...values: (string | undefined)[]): boolean {
    const q = this.query().trim().toLowerCase();
    return !q || values.some((v) => (v ?? '').toLowerCase().includes(q));
  }
  readonly ips = computed(() => (this.data()?.activeIps ?? []).filter((i) => this.match(i.ip, i.ipKey, i.lastPath, i.userAgent)));
  readonly items = computed(() => (this.data()?.items ?? []).filter((r) => this.match(r.ip, r.ipKey, r.path, r.userAgent, r.host, r.action)));
  readonly pageSafe = computed(() => Math.min(this.page(), pageCount(this.items().length)));
  readonly shown = computed(() => pageOf(this.items(), this.pageSafe()));

  constructor() {
    effect(() => {
      this.ui.changed();
      this.ui.site();
      untracked(() => void this.load());
    });
  }

  async load(): Promise<void> {
    const seq = ++this.loadSeq;
    try {
      const d = await this.api.recent(this.ui.site());
      if (seq === this.loadSeq) this.data.set(d);
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
