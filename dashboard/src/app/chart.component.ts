import { Component, ElementRef, OnDestroy, afterNextRender, computed, inject, input, signal } from '@angular/core';
import { I18n, TPipe } from './i18n';

/** Una línea del gráfico: clave de traducción de su nombre y un valor por punto. */
export interface ChartSeries {
  key: string;
  values: number[];
}

const HEIGHT = 260;
const PAD = { top: 12, right: 14, bottom: 26, left: 46 };

/** Valor redondo inmediatamente superior (1, 2, 5 × 10ⁿ) para el tope del eje Y. */
function niceMax(v: number): number {
  if (v <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(v));
  const n = v / pow;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * pow;
}

/**
 * Gráfico de líneas en el tiempo (hasta 3 series, un solo eje). SVG propio, sin librerías:
 * leyenda con totales, cursor vertical con los valores de todas las series y vista de tabla.
 */
@Component({
  selector: 'sg-chart',
  imports: [TPipe],
  template: `
  <div class="legend">
    @for (s of series(); track s.key; let i = $index) {
      <span class="legend-item"><span [class]="'swatch bg' + (i + 1)"></span>{{ s.key | t }}
        <b>{{ fmt(total(s)) }}</b></span>
    }
    <span class="spacer"></span>
    <button class="small ghost" (click)="table.set(!table())">{{ (table() ? 'ch.hideTable' : 'ch.showTable') | t }}</button>
  </div>
  <div class="plot" (pointermove)="move($event)" (pointerleave)="hover.set(null)">
    <svg [attr.width]="width()" [attr.height]="height" role="img" [attr.aria-label]="'ch.aria' | t">
      @for (g of grid(); track g.value) {
        <line class="grid" [attr.x1]="pad.left" [attr.x2]="width() - pad.right" [attr.y1]="g.y" [attr.y2]="g.y" />
        <text class="tick" [attr.x]="pad.left - 8" [attr.y]="g.y + 4" text-anchor="end">{{ fmt(g.value) }}</text>
      }
      @for (x of xTicks(); track x.i) {
        <text class="tick" [attr.x]="x.x" [attr.y]="height - 6" text-anchor="middle">{{ x.label }}</text>
      }
      @for (s of series(); track s.key; let i = $index) {
        <polyline [class]="'line s' + (i + 1)" [attr.points]="points(s)" />
      }
      @if (hover(); as h) {
        <line class="cross" [attr.x1]="x(h)" [attr.x2]="x(h)" [attr.y1]="pad.top" [attr.y2]="height - pad.bottom" />
        @for (s of series(); track s.key; let i = $index) {
          <circle [class]="'dot s' + (i + 1)" r="4" [attr.cx]="x(h)" [attr.cy]="y(s.values[h] ?? 0)" />
        }
      }
    </svg>
    @if (hover(); as h) {
      <div class="tip" [style.left.px]="tipLeft(h)">
        <div class="tip-time">{{ i18n.date(times()[h]) }}</div>
        @for (s of series(); track s.key; let i = $index) {
          <div class="tip-row"><span [class]="'key bg' + (i + 1)"></span><b>{{ fmt(s.values[h] ?? 0) }}</b>{{ s.key | t }}</div>
        }
      </div>
    }
  </div>
  @if (table()) {
    <div class="scroll chart-table"><table>
      <tr><th>{{ 'ev.time' | t }}</th>@for (s of series(); track s.key) { <th class="num">{{ s.key | t }}</th> }</tr>
      @for (t of times(); track t; let r = $index) {
        <tr><td>{{ i18n.date(t) }}</td>@for (s of series(); track s.key) { <td class="num">{{ fmt(s.values[r] ?? 0) }}</td> }</tr>
      }
    </table></div>
  }
  `,
})
export class ChartComponent implements OnDestroy {
  readonly i18n = inject(I18n);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  /** instante (ms) de cada punto, de más antiguo a más reciente */
  readonly times = input.required<number[]>();
  readonly series = input.required<ChartSeries[]>();

  readonly height = HEIGHT;
  readonly pad = PAD;
  readonly width = signal(800);
  /** índice del punto bajo el cursor */
  readonly hover = signal<number | null>(null);
  readonly table = signal(false);
  private observer: ResizeObserver | null = null;

  readonly max = computed(() => niceMax(Math.max(0, ...this.series().flatMap((s) => s.values))));
  readonly grid = computed(() => [0, 1, 2, 3, 4].map((i) => ({ value: (this.max() / 4) * i, y: this.y((this.max() / 4) * i) })));
  /** Unas 6 etiquetas de hora repartidas por el eje X */
  readonly xTicks = computed(() => {
    const n = this.times().length;
    const every = Math.max(1, Math.ceil(n / 6));
    const out: { i: number; x: number; label: string }[] = [];
    for (let i = Math.floor(every / 2); i < n; i += every) out.push({ i, x: this.x(i), label: this.clock(this.times()[i]!) });
    return out;
  });

  constructor() {
    afterNextRender(() => {
      const el = this.host.nativeElement;
      this.observer = new ResizeObserver(() => this.width.set(Math.max(320, el.clientWidth)));
      this.observer.observe(el);
    });
  }

  ngOnDestroy(): void {
    this.observer?.disconnect();
  }

  x(i: number): number {
    const n = Math.max(1, this.times().length - 1);
    return PAD.left + (i / n) * (this.width() - PAD.left - PAD.right);
  }

  y(v: number): number {
    return PAD.top + (1 - v / this.max()) * (HEIGHT - PAD.top - PAD.bottom);
  }

  points(s: ChartSeries): string {
    return this.times().map((_, i) => `${this.x(i).toFixed(1)},${this.y(s.values[i] ?? 0).toFixed(1)}`).join(' ');
  }

  total(s: ChartSeries): number {
    return s.values.reduce((a, b) => a + b, 0);
  }

  /** El cursor busca la X: se toma el punto más cercano, sin tener que acertar en una línea. */
  move(e: PointerEvent): void {
    const n = this.times().length;
    if (n === 0) return;
    const left = (e.currentTarget as HTMLElement).getBoundingClientRect().left;
    const ratio = (e.clientX - left - PAD.left) / (this.width() - PAD.left - PAD.right);
    this.hover.set(Math.min(n - 1, Math.max(0, Math.round(ratio * (n - 1)))));
  }

  /** La etiqueta flotante pasa al otro lado del cursor en la mitad derecha, para no salirse. */
  tipLeft(i: number): number {
    return this.x(i) > this.width() / 2 ? this.x(i) - 282 : this.x(i) + 12;
  }

  fmt(v: number): string {
    return v >= 10_000 ? `${(v / 1000).toFixed(v >= 100_000 ? 0 : 1)}k` : String(Math.round(v));
  }

  private clock(ms: number): string {
    return new Date(ms).toLocaleTimeString(this.i18n.lang() === 'es' ? 'es-ES' : 'en-US', { hour: '2-digit', minute: '2-digit' });
  }
}
