import { Component, ElementRef, HostListener, computed, inject, signal } from '@angular/core';
import { TPipe } from './i18n';
import { Ui } from './ui';

/**
 * Selector de sitio con buscador: con muchos sitios protegidos, una lista desplegable sin filtro
 * obliga a recorrerla entera. Escribir filtra; Enter elige el primero; Escape o un clic fuera cierra.
 */
@Component({
  selector: 'sg-site-picker',
  imports: [TPipe],
  template: `
  <div class="picker">
    <span class="muted">{{ 'site.label' | t }}</span>
    <button type="button" class="picker-btn" aria-haspopup="listbox" [attr.aria-expanded]="open()" (click)="toggle()">
      <span class="picker-value">{{ ui.site() || ('site.all' | t) }}</span><span aria-hidden="true">▾</span></button>
    @if (open()) {
      <div class="picker-pop">
        <input type="search" [placeholder]="'site.search' | t" [attr.aria-label]="'site.search' | t" [value]="query()"
               (input)="query.set($any($event.target).value)" (keydown.enter)="$event.preventDefault(); pick(first())" (keydown.escape)="close()">
        <ul role="listbox">
          @if (!query().trim()) {
            <li><button type="button" role="option" [class.active]="ui.site() === ''" (click)="pick('')">{{ 'site.all' | t }}</button></li>
          }
          @for (h of filtered(); track h) {
            <li><button type="button" role="option" [class.active]="ui.site() === h" (click)="pick(h)">{{ h }}</button></li>
          } @empty {
            @if (query().trim()) { <li class="muted picker-empty">{{ 'site.noMatch' | t }}</li> }
          }
        </ul>
      </div>
    }
  </div>
  `,
})
export class SitePickerComponent {
  readonly ui = inject(Ui);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  readonly open = signal(false);
  readonly query = signal('');
  readonly filtered = computed(() => {
    const q = this.query().trim().toLowerCase();
    return this.ui.siteOptions().filter((h) => !q || h.includes(q));
  });
  /** Lo que elige Enter: el primer resultado; sin texto, "todos los sitios". */
  readonly first = computed(() => (this.query().trim() ? (this.filtered()[0] ?? null) : ''));

  toggle(): void {
    this.open.set(!this.open());
    this.query.set('');
    // el campo de búsqueda recibe el foco al abrir, para escribir directamente
    if (this.open()) setTimeout(() => this.host.nativeElement.querySelector('input')?.focus());
  }

  close(): void {
    this.open.set(false);
    this.host.nativeElement.querySelector<HTMLElement>('.picker-btn')?.focus();
  }

  pick(site: string | null): void {
    if (site === null) return;
    this.ui.site.set(site);
    this.close();
  }

  @HostListener('document:click', ['$event'])
  outside(e: Event): void {
    if (this.open() && !this.host.nativeElement.contains(e.target as Node)) this.open.set(false);
  }
}
