import { Injectable, signal } from '@angular/core';

/** Texto que se genera en cada render: así se re-traduce al cambiar de idioma. */
export type Text = () => string;

export interface Notice {
  id: number;
  kind: 'ok' | 'warn' | 'error';
  text: Text;
}

export type Tab = 'overview' | 'manage' | 'blocked' | 'allowlist' | 'events';

/** Filtros de la pestaña Eventos (los fija también cada tarjeta del Resumen al pulsarla). */
export type EventFilter = 'all' | 'log' | 'suspicious' | 'wouldBlock' | 'blocked' | 'limited' | 'st403' | 'st429' | 'denied';

/** Avisos (toasts) + "tick" de refresco + navegación compartidos entre pestañas. */
@Injectable({ providedIn: 'root' })
export class Ui {
  readonly tab = signal<Tab>('manage');
  readonly eventFilter = signal<EventFilter>('all');
  /** Texto libre de la pestaña Eventos (IP, ruta, regla…) */
  readonly eventQuery = signal('');
  /** Pestaña Bloqueadas: incluir los bloqueos simulados de AUDIT */
  readonly showAuditBans = signal(false);
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

  openEvents(filter: EventFilter, query = ''): void {
    this.eventFilter.set(filter);
    this.eventQuery.set(query);
    this.tab.set('events');
  }

  openBans(audit: boolean): void {
    this.showAuditBans.set(audit);
    this.tab.set('blocked');
  }
}
