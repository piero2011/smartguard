import { Injectable, signal } from '@angular/core';

/** Texto que se genera en cada render: así se re-traduce al cambiar de idioma. */
export type Text = () => string;

export interface Notice {
  id: number;
  kind: 'ok' | 'warn' | 'error';
  text: Text;
}

/** Avisos (toasts) + "tick" de refresco compartido entre pestañas. */
@Injectable({ providedIn: 'root' })
export class Ui {
  readonly notices = signal<Notice[]>([]);
  /** Se incrementa tras cualquier cambio (ban, unban, allow…) para que las tablas se recarguen. */
  readonly changed = signal(0);
  /** Panel "¿por qué?" de una IP */
  readonly inspect = signal<{ ip: string; text: string } | null>(null);
  private seq = 0;

  notify(kind: Notice['kind'], text: Text): void {
    const id = ++this.seq;
    this.notices.update((n) => [...n, { id, kind, text }].slice(-5));
    setTimeout(() => this.dismiss(id), kind === 'error' ? 12_000 : 7_000);
  }

  dismiss(id: number): void {
    this.notices.update((n) => n.filter((x) => x.id !== id));
  }

  bump(): void {
    this.changed.update((v) => v + 1);
  }
}
