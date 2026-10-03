import { Component, computed, input, output } from '@angular/core';
import { TPipe } from './i18n';

/** Filas por página en todas las tablas del panel. */
export const PAGE_SIZE = 50;

export function pageCount(total: number): number {
  return Math.max(1, Math.ceil(total / PAGE_SIZE));
}

/** Filas de la página `page` (1…n) de una lista ya cargada. */
export function pageOf<T>(items: readonly T[], page: number): T[] {
  return items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
}

/** Paginador de las tablas con total conocido. No se muestra si todo cabe en una página. */
@Component({
  selector: 'sg-pager',
  imports: [TPipe],
  template: `
  @if (pages() > 1) {
    <div class="row between">
      <span class="muted">{{ 'pg.info' | t: { page: page(), pages: pages(), total: total() } }}</span>
      <div class="row">
        <button class="small" [disabled]="page() <= 1" (click)="go.emit(1)">{{ 'pg.first' | t }}</button>
        <button class="small" [disabled]="page() <= 1" (click)="go.emit(page() - 1)">{{ 'pg.prev' | t }}</button>
        <button class="small" [disabled]="page() >= pages()" (click)="go.emit(page() + 1)">{{ 'pg.next' | t }}</button>
        <button class="small" [disabled]="page() >= pages()" (click)="go.emit(pages())">{{ 'pg.last' | t }}</button>
      </div>
    </div>
  }
  `,
})
export class PagerComponent {
  readonly page = input.required<number>();
  readonly total = input.required<number>();
  readonly pages = computed(() => pageCount(this.total()));
  readonly go = output<number>();
}
