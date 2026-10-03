import { Component, inject, signal } from '@angular/core';
import { Api, ApiErr, PanelRule, panelRuleBody } from './api.service';
import { I18n, TPipe } from './i18n';
import { Ui } from './ui';

/** Mismo formato que escribe "smartguard backup" en state.json (src/admin/state-cli.ts). */
interface SavedState {
  version: 1;
  exportedAt: number;
  audit: boolean | null;
  allow: { value: string; type: string; target?: string; note?: string; expiresAt?: number }[];
  bans: { ip: string; scope: string; source: string; reason: string; expiresAt: number; audit?: boolean }[];
  bots: { pattern: string; note?: string; expiresAt?: number }[];
  networks: { asn: number; note?: string }[];
  rules?: PanelRule[];
}

interface Step {
  path: string;
  body: Record<string, unknown>;
}

/** La API admite 120 peticiones por minuto: se deja un margen entre una y otra. */
const PACE_MS = 600;

function remaining(expiresAt: number | undefined, now: number): string | null | undefined {
  if (expiresAt === undefined) return undefined;
  const sec = Math.floor((expiresAt - now) / 1000);
  if (sec <= 0) return null;
  return sec <= 9_999_999 ? String(sec) : `${Math.ceil(sec / 86_400)}d`;
}

/** Peticiones que reproducen una copia. Lo caducado y los bloqueos automáticos se omiten. */
export function importSteps(s: SavedState, now = Date.now()): Step[] {
  const steps: Step[] = [];
  for (const r of s.rules ?? []) {
    steps.push({ path: '/admin/panel-rules', body: panelRuleBody(r) });
  }
  for (const a of s.allow ?? []) {
    const ttl = remaining(a.expiresAt, now);
    if (ttl !== null) steps.push({ path: '/admin/allow', body: { value: a.value, type: a.type, target: a.target ?? 'client', note: a.note || undefined, ttl, unban: false } });
  }
  for (const b of s.bots ?? []) {
    const ttl = remaining(b.expiresAt, now);
    if (ttl !== null) steps.push({ path: '/admin/blocked-bots', body: { pattern: b.pattern, note: b.note || undefined, ttl } });
  }
  for (const n of s.networks ?? []) steps.push({ path: '/admin/blocked-networks', body: { asn: n.asn, note: n.note || undefined } });
  for (const b of s.bans ?? []) {
    if (b.source !== 'MANUAL' || b.scope !== 'ip' || b.audit) continue;
    const duration = remaining(b.expiresAt, now);
    if (duration) steps.push({ path: '/admin/ban', body: { ip: b.ip, duration, reason: (b.reason || 'import').slice(0, 200) } });
  }
  return steps;
}

/** Exportar e importar, desde el navegador, lo que se gestiona en el panel. */
@Component({
  selector: 'sg-backup',
  imports: [TPipe],
  template: `
  <section class="card">
    <h2>{{ 'bk.exportTitle' | t }}</h2>
    <p class="muted sub">{{ 'bk.exportHint' | t }}</p>
    <button class="primary" [disabled]="busy()" (click)="export()">{{ 'bk.export' | t }}</button>
  </section>

  <section class="card">
    <h2>{{ 'bk.importTitle' | t }}</h2>
    <p class="muted sub">{{ 'bk.importHint' | t }}</p>
    <input type="file" accept="application/json,.json" [disabled]="busy()" (change)="pickFile($event)">
    @if (loaded(); as s) {
      <div class="status">
        <p>{{ 'bk.fileInfo' | t: { date: i18n.date(s.exportedAt), rules: (s.rules ?? []).length, allow: s.allow.length, bans: manualBans(s), bots: s.bots.length, networks: s.networks.length } }}</p>
        <div class="row">
          <button class="primary" [disabled]="busy()" (click)="import(s)">{{ 'bk.import' | t: { count: steps(s) } }}</button>
          @if (busy()) { <span class="muted">{{ 'bk.progress' | t: { done: done(), total: total() } }}</span> }
        </div>
      </div>
    }
    @if (result(); as r) { <p class="msg" [class.ok]="r.failed === 0" [class.warn]="r.failed > 0">{{ 'bk.result' | t: r }}</p> }
    @for (e of errors(); track $index) { <p class="msg error">{{ e }}</p> }
  </section>

  <section class="card">
    <h2>{{ 'bk.fullTitle' | t }}</h2>
    @if (ui.deployment() === 'docker') {
      <p class="muted">{{ 'bk.fullDocker' | t }}</p>
    } @else {
      <p class="muted">{{ 'bk.fullHint' | t }}</p>
      <pre class="snippet">sudo smartguard backup
sudo smartguard restore /root/smartguard-backup-….tar.gz</pre>
    }
  </section>
  `,
})
export class BackupComponent {
  private readonly api = inject(Api);
  readonly ui = inject(Ui);
  readonly i18n = inject(I18n);
  readonly busy = signal(false);
  readonly loaded = signal<SavedState | null>(null);
  readonly done = signal(0);
  readonly total = signal(0);
  readonly result = signal<{ ok: number; already: number; failed: number } | null>(null);
  readonly errors = signal<string[]>([]);

  manualBans(s: SavedState): number {
    return s.bans.filter((b) => b.source === 'MANUAL' && b.scope === 'ip' && !b.audit).length;
  }
  steps(s: SavedState): number {
    return importSteps(s).length;
  }

  async export(): Promise<void> {
    this.busy.set(true);
    try {
      const bans: SavedState['bans'] = [];
      for (let offset = 0; ; offset += 500) {
        const page = await this.api.bans(false, offset, 500);
        bans.push(...page.items);
        if (page.items.length < 500) break;
      }
      const state: SavedState = {
        version: 1,
        exportedAt: Date.now(),
        audit: (await this.api.mode()).audit,
        allow: (await this.api.allowlist()).dynamic ?? [],
        bans,
        bots: (await this.api.blockedBots()).items,
        networks: (await this.api.blockedNetworks()).items.map((n) => ({ asn: n.asn, note: n.note })),
        rules: (await this.api.panelRules()).items,
      };
      const url = URL.createObjectURL(new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `smartguard-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      this.ui.notify('ok', () => this.i18n.t('bk.exported'));
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    } finally {
      this.busy.set(false);
    }
  }

  async pickFile(ev: Event): Promise<void> {
    this.loaded.set(null);
    this.result.set(null);
    this.errors.set([]);
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;
    try {
      const s = JSON.parse(await file.text()) as SavedState;
      if (s.version !== 1 || !Array.isArray(s.allow) || !Array.isArray(s.bans) || !Array.isArray(s.bots) || !Array.isArray(s.networks)) throw new Error('format');
      this.loaded.set(s);
    } catch {
      this.errors.set([this.i18n.t('bk.badFile')]);
    }
  }

  async import(s: SavedState): Promise<void> {
    const steps = importSteps(s);
    if (!confirm(this.i18n.t('bk.confirm', { count: steps.length }))) return;
    this.busy.set(true);
    this.result.set(null);
    this.errors.set([]);
    this.done.set(0);
    this.total.set(steps.length);
    let ok = 0;
    let already = 0;
    const failed: string[] = [];
    for (const step of steps) {
      for (let attempt = 0; ; attempt++) {
        try {
          await this.api.post(step.path, step.body);
          ok++;
        } catch (e) {
          const err = e as ApiErr;
          // límite de peticiones: se espera y se repite la misma entrada
          if (err.status === 429 && attempt < 5) {
            await new Promise((r) => setTimeout(r, 15_000));
            continue;
          }
          if (err.status === 409) already++;
          else failed.push(`${String(step.body['id'] ?? step.body['value'] ?? step.body['ip'] ?? step.body['pattern'] ?? step.body['asn'])}: ${this.api.describe(err)}`);
        }
        break;
      }
      this.done.update((n) => n + 1);
      await new Promise((r) => setTimeout(r, PACE_MS));
    }
    this.result.set({ ok, already, failed: failed.length });
    this.errors.set(failed.slice(0, 20));
    this.busy.set(false);
    this.ui.bump();
  }
}
