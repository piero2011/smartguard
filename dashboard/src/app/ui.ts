import { Injectable, inject, signal } from '@angular/core';
import { Api, ApiErr, PERMANENT } from './api.service';
import { I18n } from './i18n';

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

/** Acciones de bloqueo compartidas por las tablas (Resumen, Eventos). */
@Injectable({ providedIn: 'root' })
export class BlockActions {
  private readonly api = inject(Api);
  private readonly ui = inject(Ui);
  private readonly i18n = inject(I18n);

  /**
   * Bloquea una IP hasta que se desbloquee a mano (pestaña Bloqueadas). Vale para todas sus
   * peticiones siguientes, también en AUDIT. Acepta una clave IPv6 con prefijo ("2001:db8::/64").
   */
  async blockIp(ipOrKey: string): Promise<void> {
    const ip = ipOrKey.split('/')[0] ?? ipOrKey;
    if (!confirm(this.i18n.t('ev.confirmBlockIp', { ip }))) return;
    try {
      await this.api.ban({ ip, duration: PERMANENT, reason: 'dashboard' });
      this.ui.notify('ok', () => this.i18n.t('ev.ipBlocked', { ip }));
      this.ui.bump();
    } catch (err) {
      this.ui.notify('error', () => this.api.describe(err as ApiErr));
    }
  }

  /**
   * Bloquea la red entera (ASN) a la que pertenece una IP: todos los rangos de ese proveedor,
   * hasta que se desbloquee a mano. `org` es solo para el texto de confirmación.
   */
  async blockNetwork(ipOrKey: string, org: string): Promise<void> {
    const ip = ipOrKey.split('/')[0] ?? ipOrKey;
    if (!confirm(this.i18n.t('net.confirmBlock', { org: org || ip }))) return;
    try {
      const n = await this.api.blockNetwork({ ip });
      this.ui.notify('ok', () => this.i18n.t('net.blocked', { org: n.org, asn: n.asn, count: n.prefixCount }));
      this.ui.bump();
    } catch (err) {
      this.ui.notify('error', () => this.api.describe(err as ApiErr));
    }
  }
}
