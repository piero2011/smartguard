import { Component, computed, inject, signal } from '@angular/core';
import { Api, ApiErr, PanelRule, RuleInfo } from './api.service';
import { I18n, TPipe } from './i18n';
import { Ui } from './ui';
import { PagerComponent, pageCount, pageOf } from './pager.component';

const TARGETS: PanelRule['target'][] = ['path', 'query', 'uri', 'ua', 'method'];
const ACTIONS: NonNullable<PanelRule['action']>[] = ['score', 'block', 'allow'];
const SEVERITIES: PanelRule['severity'][] = ['low', 'medium', 'high', 'critical'];
const CONFIDENCES: NonNullable<PanelRule['confidence']>[] = ['low', 'medium', 'high'];
const CATEGORIES = ['SCANNER', 'SENSITIVE_FILE', 'WP_SCAN', 'LOGIN_ABUSE', 'XMLRPC_ABUSE', 'SQLI', 'XSS', 'TRAVERSAL', 'RCE', 'WEBSHELL_SCAN', 'BAD_BOT', 'RATE_SPIKE', 'NORMAL', 'UNKNOWN'];

interface Form {
  id: string;
  name: string;
  target: PanelRule['target'];
  /** contains = el texto tal cual (se escapa) · regex = expresión regular */
  mode: 'contains' | 'regex';
  text: string;
  methods: string;
  action: NonNullable<PanelRule['action']>;
  score: number;
  severity: PanelRule['severity'];
  confidence: NonNullable<PanelRule['confidence']>;
  category: string;
  enabled: boolean;
}

const EMPTY: Form = { id: '', name: '', target: 'path', mode: 'contains', text: '', methods: '', action: 'score', score: 20, severity: 'medium', confidence: 'medium', category: 'SCANNER', enabled: true };

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Reglas: las propias (se crean, editan, desactivan y borran aquí) y las incluidas (solo lectura). */
@Component({
  selector: 'sg-rules',
  imports: [TPipe, PagerComponent],
  template: `
  <section class="card">
    <h2>{{ (editing() ? 'ru.editTitle' : 'ru.addTitle') | t }}</h2>
    <p class="muted sub">{{ 'ru.addHint' | t }}</p>
    <div class="grid2">
      <label>{{ 'ru.id' | t }}
        <input [value]="form().id" [disabled]="editing()" (input)="set('id', $any($event.target).value.toLowerCase())" placeholder="mi-regla" maxlength="64" spellcheck="false"></label>
      <label>{{ 'ru.name' | t }}
        <input [value]="form().name" (input)="set('name', $any($event.target).value)" maxlength="120"></label>
      <label>{{ 'ru.target' | t }}
        <select (change)="set('target', $any($event.target).value)">
          @for (x of targets; track x) { <option [value]="x" [selected]="form().target === x">{{ ('ru.target.' + x) | t }}</option> }
        </select></label>
      <label>{{ 'ru.mode' | t }}
        <select (change)="set('mode', $any($event.target).value)">
          <option value="contains" [selected]="form().mode === 'contains'">{{ 'ru.mode.contains' | t }}</option>
          <option value="regex" [selected]="form().mode === 'regex'">{{ 'ru.mode.regex' | t }}</option>
        </select></label>
    </div>
    <label>{{ (form().mode === 'contains' ? 'ru.text' : 'ru.pattern') | t }}
      <input [value]="form().text" (input)="set('text', $any($event.target).value)" maxlength="500" spellcheck="false"
             [placeholder]="form().mode === 'contains' ? '/phpmyadmin' : '^/(?:phpmyadmin|pma)(?:/|$)'"></label>
    <div class="grid2">
      <label>{{ 'ru.action' | t }}
        <select (change)="set('action', $any($event.target).value)">
          @for (x of actions; track x) { <option [value]="x" [selected]="form().action === x">{{ ('ru.action.' + x) | t }}</option> }
        </select></label>
      <label>{{ 'ru.score' | t }}
        <input type="number" min="0" max="1000" [value]="form().score" [disabled]="form().action === 'allow'" (input)="set('score', +$any($event.target).value)"></label>
      <label>{{ 'ru.severity' | t }}
        <select (change)="set('severity', $any($event.target).value)">
          @for (x of severities; track x) { <option [value]="x" [selected]="form().severity === x">{{ ('ru.sev.' + x) | t }}</option> }
        </select></label>
      <label>{{ 'ru.confidence' | t }}
        <select (change)="set('confidence', $any($event.target).value)">
          @for (x of confidences; track x) { <option [value]="x" [selected]="form().confidence === x">{{ ('ru.conf.' + x) | t }}</option> }
        </select></label>
      <label>{{ 'ru.category' | t }}
        <select (change)="set('category', $any($event.target).value)">
          @for (x of categories; track x) { <option [value]="x" [selected]="form().category === x">{{ x }}</option> }
        </select></label>
      <label>{{ 'ru.methods' | t }}
        <input [value]="form().methods" (input)="set('methods', $any($event.target).value.toUpperCase())" placeholder="GET,POST" maxlength="60"></label>
    </div>
    <label class="check"><input type="checkbox" [checked]="form().enabled" (change)="set('enabled', $any($event.target).checked)"> {{ 'ru.enabled' | t }}</label>
    <p class="muted">{{ ('ru.actionHint.' + form().action) | t }}</p>
    <div class="row">
      <button class="primary" [disabled]="!valid() || saving()" (click)="save()">{{ (editing() ? 'ru.saveChanges' : 'ru.add') | t }}</button>
      @if (editing()) { <button (click)="reset()">{{ 'ru.cancel' | t }}</button> }
    </div>
    @if (error()) { <p class="msg error">{{ error() }}</p> }
  </section>

  <section class="card">
    <div class="row between">
      <h2>{{ 'ru.mine' | t }} ({{ mine().length }})</h2>
      <input type="search" [placeholder]="'ru.search' | t" [value]="query()" (input)="query.set($any($event.target).value); minePage.set(1); builtinPage.set(1)">
    </div>
    <div class="scroll"><table>
      <tr><th>{{ 'ru.id' | t }}</th><th>{{ 'ru.target' | t }}</th><th>{{ 'ru.pattern' | t }}</th><th>{{ 'ru.action' | t }}</th>
        <th class="num">{{ 'ru.score' | t }}</th><th>{{ 'ru.state' | t }}</th><th></th></tr>
      @for (r of mineShown(); track r.id) {
        <tr>
          <td><code>{{ r.id }}</code><span class="ua">{{ r.name }}</span></td>
          <td class="nowrap">{{ ('ru.target.' + (r.target ?? 'path')) | t }}</td>
          <td class="uri"><code [title]="r.pattern">{{ r.pattern }}</code></td>
          <td class="nowrap">{{ ('ru.action.' + (r.action ?? 'score')) | t }}</td>
          <td class="num">{{ r.score }}</td>
          <td><span class="pill" [class.enforce]="r.enabled !== false" [class.off]="r.enabled === false">{{ (r.enabled === false ? 'ru.off' : 'ru.on') | t }}</span></td>
          <td class="actions">
            <button class="small" (click)="edit(r)">{{ 'ru.edit' | t }}</button>
            <button class="small" (click)="toggle(r)">{{ (r.enabled === false ? 'ru.enable' : 'ru.disable') | t }}</button>
            <button class="small danger" (click)="remove(r)">{{ 'ru.delete' | t }}</button>
          </td>
        </tr>
      } @empty { <tr><td colspan="7" class="muted">{{ (query() ? 'ru.noMatch' : 'ru.noneMine') | t }}</td></tr> }
    </table></div>
    <sg-pager [page]="minePageSafe()" [total]="mine().length" (go)="minePage.set($event)" />
  </section>

  <section class="card">
    <h2>{{ 'ru.builtin' | t }} ({{ builtin().length }})</h2>
    <p class="muted sub">{{ 'ru.builtinHint' | t }}</p>
    <div class="scroll"><table>
      <tr><th>{{ 'ru.id' | t }}</th><th>{{ 'ru.target' | t }}</th><th>{{ 'ru.pattern' | t }}</th><th>{{ 'ru.action' | t }}</th>
        <th class="num">{{ 'ru.score' | t }}</th><th>{{ 'ru.category' | t }}</th></tr>
      @for (r of builtinShown(); track r.id) {
        <tr>
          <td><code>{{ r.id }}</code><span class="ua">{{ r.name }}</span></td>
          <td class="nowrap">{{ ('ru.target.' + r.target) | t }}</td>
          <td class="uri"><code [title]="r.pattern">{{ r.pattern }}</code></td>
          <td class="nowrap">{{ ('ru.action.' + r.action) | t }}</td>
          <td class="num">{{ r.score }}</td>
          <td class="nowrap">{{ r.category }}</td>
        </tr>
      } @empty { <tr><td colspan="6" class="muted">{{ (query() ? 'ru.noMatch' : 'common.none') | t }}</td></tr> }
    </table></div>
    <sg-pager [page]="builtinPageSafe()" [total]="builtin().length" (go)="builtinPage.set($event)" />
  </section>
  `,
})
export class RulesComponent {
  private readonly api = inject(Api);
  private readonly ui = inject(Ui);
  private readonly i18n = inject(I18n);
  readonly targets = TARGETS;
  readonly actions = ACTIONS;
  readonly severities = SEVERITIES;
  readonly confidences = CONFIDENCES;
  readonly categories = CATEGORIES;

  readonly form = signal<Form>({ ...EMPTY });
  readonly editing = signal(false);
  readonly saving = signal(false);
  readonly error = signal('');
  readonly query = signal('');
  private readonly panel = signal<PanelRule[]>([]);
  private readonly all = signal<RuleInfo[]>([]);
  readonly minePage = signal(1);
  readonly builtinPage = signal(1);

  private matches(...values: (string | undefined)[]): boolean {
    const q = this.query().trim().toLowerCase();
    return !q || values.some((v) => (v ?? '').toLowerCase().includes(q));
  }
  readonly mine = computed(() => this.panel().filter((r) => this.matches(r.id, r.name, r.pattern, r.category)));
  readonly builtin = computed(() => this.all().filter((r) => r.source !== 'panel' && this.matches(r.id, r.name, r.pattern, r.category)));
  readonly minePageSafe = computed(() => Math.min(this.minePage(), pageCount(this.mine().length)));
  readonly builtinPageSafe = computed(() => Math.min(this.builtinPage(), pageCount(this.builtin().length)));
  readonly mineShown = computed(() => pageOf(this.mine(), this.minePageSafe()));
  readonly builtinShown = computed(() => pageOf(this.builtin(), this.builtinPageSafe()));

  readonly valid = computed(() => /^[a-z0-9][a-z0-9_.-]{1,63}$/.test(this.form().id) && this.form().text.trim().length > 0);

  constructor() {
    void this.load();
  }

  set<K extends keyof Form>(key: K, value: Form[K]): void {
    this.form.update((f) => ({ ...f, [key]: value }));
  }

  async load(): Promise<void> {
    try {
      const [panel, all] = await Promise.all([this.api.panelRules(), this.api.rules()]);
      this.panel.set(panel.items);
      this.all.set(all.rules);
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  private toRule(f: Form): PanelRule {
    const allow = f.action === 'allow';
    return {
      id: f.id,
      name: f.name.trim() || f.id,
      enabled: f.enabled,
      target: f.target,
      pattern: f.mode === 'contains' ? escapeRegex(f.text.trim()) : f.text.trim(),
      methods: f.methods.trim() || undefined,
      score: allow ? 0 : f.score,
      severity: f.severity,
      confidence: f.confidence,
      category: allow ? 'NORMAL' : f.category,
      action: f.action,
    };
  }

  async save(): Promise<void> {
    this.error.set('');
    this.saving.set(true);
    try {
      const r = await this.api.savePanelRule(this.toRule(this.form()));
      this.ui.notify('ok', () => this.i18n.t('ru.saved', { id: r.rule.id }));
      this.reset();
      await this.load();
    } catch (e) {
      this.error.set(this.api.describe(e as ApiErr));
    } finally {
      this.saving.set(false);
    }
  }

  edit(r: PanelRule): void {
    this.form.set({
      id: r.id,
      name: r.name ?? '',
      target: r.target ?? 'path',
      mode: 'regex',
      text: r.pattern,
      methods: Array.isArray(r.methods) ? r.methods.join(',') : (r.methods ?? ''),
      action: r.action ?? 'score',
      score: r.score,
      severity: r.severity,
      confidence: r.confidence ?? 'medium',
      category: r.category,
      enabled: r.enabled !== false,
    });
    this.editing.set(true);
    this.error.set('');
    scrollTo({ top: 0, behavior: 'smooth' });
  }

  reset(): void {
    this.form.set({ ...EMPTY });
    this.editing.set(false);
    this.error.set('');
  }

  async toggle(r: PanelRule): Promise<void> {
    try {
      await this.api.savePanelRule({ ...r, enabled: r.enabled === false });
      await this.load();
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }

  async remove(r: PanelRule): Promise<void> {
    if (!confirm(this.i18n.t('ru.confirmDelete', { id: r.id }))) return;
    try {
      await this.api.deletePanelRule(r.id);
      this.ui.notify('ok', () => this.i18n.t('ru.deleted', { id: r.id }));
      if (this.editing() && this.form().id === r.id) this.reset();
      await this.load();
    } catch (e) {
      this.ui.notify('error', () => this.api.describe(e as ApiErr));
    }
  }
}
