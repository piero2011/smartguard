import { Injectable, effect, inject, signal } from '@angular/core';
import { Api, ApiErr, PERMANENT } from './api.service';
import { I18n } from './i18n';

/** Texto que se genera en cada render: así se re-traduce al cambiar de idioma. */
export type Text = () => string;

export interface Notice {
  id: number;
  kind: 'ok' | 'warn' | 'error';
  text: Text;
}

export type Theme = 'light' | 'dark';
const THEME_KEY = 'sg_theme';

function readStoredTheme(): Theme {
  try {
    return localStorage.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

export type Tab = 'overview' | 'manage' | 'blocked' | 'allowlist' | 'events';

/** Filtros de la pestaña Eventos (los fija también cada tarjeta del Resumen al pulsarla). */
export type EventFilter = 'all' | 'log' | 'suspicious' | 'wouldBlock' | 'blocked' | 'limited' | 'st403' | 'st429' | 'denied';

/** Avisos (toasts) + "tick" de refresco + navegación compartidos entre pestañas. */
@Injectable({ providedIn: 'root' })
export class Ui {
  readonly tab = signal<Tab>('manage');
  /** Ventana de tiempo del Resumen, en minutos */
  readonly overviewMinutes = signal(60);
  /** Tema del panel: claro por defecto; la elección se recuerda en este navegador */
  readonly theme = signal<Theme>(readStoredTheme());
  readonly eventFilter = signal<EventFilter>('all');
  /** Texto libre de la pestaña Eventos (IP, ruta, regla…) */
  readonly eventQuery = signal('');
  /** Rango de fechas de la pestaña Eventos (valor de un <input type="datetime-local">; '' = sin límite) */
  readonly eventFrom = signal('');
  readonly eventTo = signal('');
  /** Pestaña Bloqueadas: incluir los bloqueos simulados de AUDIT */
  readonly showAuditBans = signal(false);
  readonly notices = signal<Notice[]>([]);
  /** Se incrementa tras cualquier cambio (ban, unban, allow…) para que las tablas se recarguen. */
  readonly changed = signal(0);
  /** Panel "¿por qué?" de una IP */
  readonly inspect = signal<{ ip: string; text: string } | null>(null);
  private seq = 0;

  constructor() {
    effect(() => {
      document.documentElement.dataset['theme'] = this.theme();
    });
  }

  toggleTheme(): void {
    const next: Theme = this.theme() === 'dark' ? 'light' : 'dark';
    this.theme.set(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      /* sin almacenamiento: el tema dura lo que la pestaña */
    }
  }

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

/** Productos de User-Agent que llevan los navegadores: nunca se proponen como nombre de bot. */
const BROWSER_TOKENS = new Set(['mozilla', 'applewebkit', 'chrome', 'safari', 'gecko', 'firefox', 'version', 'mobile', 'edg', 'opr', 'crios', 'fxios']);

/**
 * Propone el texto a bloquear a partir de un User-Agent: el nombre propio del bot
 * ("Mozilla/5.0 (compatible; DotBot/1.2; +https://…)" → "DotBot", "python-requests/2.31" → "python-requests").
 * Devuelve '' si parece un navegador normal (el administrador escribe el texto a mano).
 */
export function suggestBotPattern(userAgent: string): string {
  const ua = userAgent.replace(/https?:\/\/\S+/g, ' ');
  const named = /[A-Za-z][\w.-]*(?:bot|spider|crawl|scrap|scan|fetch|http|client|lib)[\w.-]*/i.exec(ua);
  if (named) return named[0].slice(0, 64);
  const product = /^\s*([A-Za-z][\w.-]{2,63})(?:\/|\s|$)/.exec(ua);
  return product && !BROWSER_TOKENS.has(product[1]!.toLowerCase()) ? product[1]! : '';
}

/**
 * Acciones de bloqueo compartidas por las tablas (Resumen, Eventos) y estado de lo que YA está
 * bloqueado, para mostrar "IP bloqueada" / "Bot bloqueado" / "Red bloqueada" en lugar del botón.
 */
@Injectable({ providedIn: 'root' })
export class BlockActions {
  private readonly api = inject(Api);
  private readonly ui = inject(Ui);
  private readonly i18n = inject(I18n);

  /** claves de IP con un bloqueo activo (manual o automático) */
  private readonly bannedKeys = signal<ReadonlySet<string>>(new Set());
  /** textos de bot bloqueados (en minúsculas) */
  private readonly botPatterns = signal<readonly string[]>([]);
  private readonly netAsns = signal<ReadonlySet<number>>(new Set());

  constructor() {
    // Se recarga al conectar (token) y tras cada cambio o refresco del panel.
    effect(() => {
      this.ui.changed();
      if (this.api.token()) void this.reload();
    });
  }

  private async reload(): Promise<void> {
    try {
      const [bans, bots, nets] = await Promise.all([this.api.bans(false), this.api.blockedBots(), this.api.blockedNetworks()]);
      this.bannedKeys.set(new Set(bans.items.filter((b) => b.scope === 'ip').map((b) => b.key)));
      this.botPatterns.set(bots.items.map((b) => b.pattern));
      this.netAsns.set(new Set(nets.items.map((n) => n.asn)));
    } catch {
      /* información auxiliar: sin ella simplemente se ofrecen los botones */
    }
  }

  /** ¿La IP (o su clave, p. ej. un /64 de IPv6) tiene ya un bloqueo activo? */
  ipBlocked(...ipOrKeys: (string | undefined)[]): boolean {
    const set = this.bannedKeys();
    return ipOrKeys.some((k) => !!k && set.has(k));
  }

  /** ¿Algún bot bloqueado por nombre coincide con este User-Agent? Devuelve el texto que coincide. */
  botBlocked(userAgent: string | undefined): string | null {
    if (!userAgent) return null;
    const ua = userAgent.toLowerCase();
    return this.botPatterns().find((p) => ua.includes(p)) ?? null;
  }

  netBlocked(asn: number | null | undefined): boolean {
    return !!asn && this.netAsns().has(asn);
  }

  /** Bloquea un bot por su nombre (texto del User-Agent), venga de la IP que venga, hasta desbloquearlo. */
  async blockBot(userAgent: string): Promise<void> {
    const pattern = prompt(this.i18n.t('ev.promptBot', { ua: userAgent }), suggestBotPattern(userAgent))?.trim();
    if (!pattern) return;
    try {
      const b = await this.api.blockBot({ pattern, note: userAgent.slice(0, 200) });
      this.ui.notify('ok', () => this.i18n.t('ev.botBlocked', { pattern: b.pattern }));
      this.ui.bump();
    } catch (err) {
      this.ui.notify('error', () => this.api.describe(err as ApiErr));
    }
  }

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
