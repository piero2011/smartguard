import { Injectable, Pipe, PipeTransform, inject, signal } from '@angular/core';

export type Lang = 'en' | 'es';
type Dict = Record<string, string>;

/**
 * Traducciones en tiempo de ejecución (sin recompilar por idioma).
 * Idioma por defecto: INGLÉS. El usuario puede cambiar a español; se recuerda en localStorage.
 * Parámetros: "{name}" en el texto.
 */
const EN: Dict = {
  'app.title': 'SmartGuard',
  'app.subtitle': 'WordPress / WooCommerce protection',
  'lang.label': 'Language',
  'auth.token': 'Admin token',
  'auth.connect': 'Connect',
  'auth.logout': 'Log out',
  'auth.hint': 'Paste the ADMIN_TOKEN from /etc/smartguard/smartguard.env. It is kept only in this browser tab.',
  'auth.invalid': 'Invalid token.',
  'mode.AUDIT': 'AUDIT (log only)',
  'mode.ENFORCE': 'ENFORCE (blocking)',
  'mode.switchToEnforce': 'Switch to ENFORCE',
  'mode.switchToAudit': 'Switch to AUDIT',
  'mode.confirmEnforce': 'Enable ENFORCE? SmartGuard will start blocking (403). Nginx rule mode is changed with: sudo smartguard audit off',
  'mode.confirmAudit': 'Switch SmartGuard back to AUDIT (log only)?',
  'tab.overview': 'Overview',
  'tab.manage': 'IPs & sites',
  'tab.blocked': 'Blocked',
  'tab.allowlist': 'Allowlist',
  'tab.events': 'Events',
  'common.refresh': 'Refresh',
  'common.remove': 'Remove',
  'common.unblock': 'Unblock',
  'common.inspect': 'Inspect',
  'common.none': 'No data',
  'common.loading': 'Loading…',
  'common.yes': 'Yes',
  'common.no': 'No',
  'common.until': 'until {date}',
  'common.updated': 'Updated {time}',
  'common.degraded': 'Redis degraded (in-memory mode)',

  'ov.decisions': 'Decisions / min',
  'ov.logLines': 'Security log lines / min',
  'ov.activeIps': 'Active IPs (5 min)',
  'ov.bans': 'Active blocks',
  'ov.wouldBans': 'Would-blocks (AUDIT)',
  'ov.suspicious': 'Suspicious (60 min)',
  'ov.sg403': '403 by SmartGuard',
  'ov.sg429': '429 by SmartGuard',
  'ov.nginx403': '403 by Nginx',
  'ov.nginx429': '429 by Nginx',
  'ov.phpAvoided': 'PHP requests avoided',
  'ov.wouldBlock': 'Would block / limit',
  'ov.topPaths': 'Top attack paths',
  'ov.topIps': 'Top IPs (points)',
  'ov.topRules': 'Top rules',
  'ov.path': 'Path',
  'ov.hits': 'Hits',
  'ov.points': 'Points',
  'ov.rule': 'Rule',

  'mg.check.title': 'Check an IP, domain or site',
  'mg.check.placeholder': 'IP, CIDR, domain, *.domain or https://site…',
  'mg.check.button': 'Check',
  'mg.check.help': 'Shows whether the value is already allowlisted (and in which list) or blocked.',
  'mg.status.notListed': '{value} is not in any list.',
  'mg.status.allowlisted': '{value} is already allowlisted:',
  'mg.status.blocked': '{value} is BLOCKED {until}.',
  'mg.status.auditBlocked': 'In AUDIT it would be blocked {until}.',
  'mg.status.fpBans': '{count} block(s) by IP + browser fingerprint.',
  'mg.status.score': 'Current score: {score}',
  'mg.status.cloudflare': 'This is a Cloudflare IP: never block it (it would block all your visitors).',
  'mg.match': '{list} · {source} · {how}{detail}',

  'mg.allow.title': 'Allow a client (who connects)',
  'mg.allow.help': 'IP, CIDR, exact domain (resolved to its IPs) or *.domain (verified by reverse DNS). Allowing an IP also unblocks it.',
  'mg.allow.value': 'IP, CIDR, domain or *.domain',
  'mg.allow.list': 'List',
  'mg.allow.note': 'Note (optional)',
  'mg.allow.ttl': 'Expires',
  'mg.allow.submit': 'Allow client',
  'mg.allow.done': '{value} added to {list}.',

  'mg.host.title': 'Allow a site or subdomain (destination)',
  'mg.host.help': 'SmartGuard will not score requests to this site. Accepts domain, *.domain or a URL (https://api.example.com/path).',
  'mg.host.value': 'domain, *.domain or URL',
  'mg.host.submit': 'Allow site',
  'mg.host.done': 'Site {value} exempted.',

  'mg.block.title': 'Block an IP',
  'mg.block.help': 'Manual block. Applies immediately (also in AUDIT mode).',
  'mg.block.ip': 'IPv4 or IPv6',
  'mg.block.duration': 'Duration',
  'mg.block.reason': 'Reason (optional)',
  'mg.block.submit': 'Block IP',
  'mg.block.done': '{ip} blocked until {until}.',

  'mg.unblock.title': 'Unblock an IP',
  'mg.unblock.help': 'Removes the IP block, fingerprint blocks, nftables and Cloudflare rules. By default it also resets its score so it is not blocked again right away.',
  'mg.unblock.keepScore': 'Keep score and history',
  'mg.unblock.submit': 'Unblock IP',
  'mg.unblock.done': '{ip} unblocked ({fp} fingerprint block(s) removed).',
  'mg.unblock.notBlocked': '{ip} was not blocked. Score reset: {reset}.',

  'ttl.never': 'Never',
  'dur.15m': '15 minutes',
  'dur.1h': '1 hour',
  'dur.6h': '6 hours',
  'dur.24h': '24 hours',
  'dur.7d': '7 days',
  'dur.30d': '30 days',
  'dur.365d': '1 year',

  'list.ADMIN_ALLOWLIST': 'Admin IPs',
  'list.SERVICE_ALLOWLIST': 'Services',
  'list.TRUSTED_NETWORK': 'Trusted networks',
  'list.ALLOW_HOSTS': 'Exempt sites',
  'source.env': '.env file',
  'source.dynamic': 'dashboard / API',
  'source.builtin': 'built-in',
  'how.exact': 'exact match',
  'how.cidr': 'inside range {value}',
  'how.domain-resolved': 'IP of domain {value}',
  'how.subdomain-verified': 'verified subdomain of {value}',
  'how.domain-pattern': 'covered by {value}',
  'how.host': 'exempt site {value}',

  'bl.title': 'Blocked IPs',
  'bl.showAudit': 'Show AUDIT would-blocks',
  'bl.ip': 'IP / key',
  'bl.score': 'Score',
  'bl.reason': 'Reason',
  'bl.scope': 'Scope',
  'bl.source': 'Source',
  'bl.count': 'Times',
  'bl.created': 'Created',
  'bl.expires': 'Expires',
  'bl.mode': 'Mode',
  'bl.action': 'Action',
  'bl.confirmUnblock': 'Unblock {ip}?',

  'al.title': 'Allowlist',
  'al.value': 'Value',
  'al.list': 'List',
  'al.target': 'Applies to',
  'al.target.client': 'client',
  'al.target.host': 'site',
  'al.origin': 'Origin / note',
  'al.resolved': 'Resolved IPs',
  'al.editEnv': 'edit .env',
  'al.confirmRemove': 'Remove {value} from the allowlist?',
  'al.removed': '{value} removed from the allowlist.',

  'ev.title': 'Recent security events',
  'ev.time': 'Time',
  'ev.action': 'Action',
  'ev.country': 'Country',
  'ev.host': 'Host',
  'ev.method': 'Method',
  'ev.uri': 'URI',
  'ev.status': 'Status',
  'ev.category': 'Category',
  'ev.delta': 'Δ',
  'ev.reason': 'Reason',

  'inspect.title': 'Why? — {ip}',
  'inspect.close': 'Close',

  'err.generic': 'Error {status}: {message}',
  'err.network': 'SmartGuard is not reachable. Is the service running and the SSH tunnel open?',
  'err.UNAUTHORIZED': 'Invalid or missing admin token.',
  'err.RATE_LIMITED': 'Too many requests. Wait a minute.',
  'err.VALIDATION': 'Invalid field "{field}": {reason}',
  'err.INVALID_VALUE': 'Invalid value. Use an IP, CIDR, domain, *.domain or site URL.',
  'err.INVALID_IP': 'Invalid IP address.',
  'err.ALREADY_ALLOWLISTED': '{value} is already in the allowlist: {lists}.',
  'err.ALREADY_COVERED': '{value} is already covered by: {lists}.',
  'err.IP_ALLOWLISTED': '{ip} is in the allowlist ({lists}). Remove it from the allowlist before blocking it.',
  'err.ALREADY_BANNED': '{ip} is already blocked until {until} ({reason}).',
  'err.CLOUDFLARE_IP': '{ip} is a Cloudflare IP. Blocking it would block all your visitors.',
  'err.NOT_IN_ALLOWLIST': '{value} is not in the allowlist.',
  'err.STATIC_ENTRY': '{value} is defined in the .env file ({lists}). Edit /etc/smartguard/smartguard.env and restart SmartGuard.',
  'err.HOST_REQUIRES_DOMAIN': 'An exempt site must be a domain, *.domain or URL, not an IP.',
  'err.RELOAD_REJECTED': 'Rules reload rejected: {error}',
};

const ES: Dict = {
  'app.title': 'SmartGuard',
  'app.subtitle': 'Protección WordPress / WooCommerce',
  'lang.label': 'Idioma',
  'auth.token': 'Token de administrador',
  'auth.connect': 'Conectar',
  'auth.logout': 'Salir',
  'auth.hint': 'Pega el ADMIN_TOKEN de /etc/smartguard/smartguard.env. Solo se guarda en esta pestaña del navegador.',
  'auth.invalid': 'Token no válido.',
  'mode.AUDIT': 'AUDIT (solo registra)',
  'mode.ENFORCE': 'ENFORCE (bloqueando)',
  'mode.switchToEnforce': 'Pasar a ENFORCE',
  'mode.switchToAudit': 'Pasar a AUDIT',
  'mode.confirmEnforce': '¿Activar ENFORCE? SmartGuard empezará a bloquear (403). El modo de las reglas Nginx se cambia con: sudo smartguard audit off',
  'mode.confirmAudit': '¿Volver SmartGuard a AUDIT (solo registra)?',
  'tab.overview': 'Resumen',
  'tab.manage': 'IPs y sitios',
  'tab.blocked': 'Bloqueadas',
  'tab.allowlist': 'Lista blanca',
  'tab.events': 'Eventos',
  'common.refresh': 'Actualizar',
  'common.remove': 'Quitar',
  'common.unblock': 'Desbloquear',
  'common.inspect': 'Detalle',
  'common.none': 'Sin datos',
  'common.loading': 'Cargando…',
  'common.yes': 'Sí',
  'common.no': 'No',
  'common.until': 'hasta {date}',
  'common.updated': 'Actualizado {time}',
  'common.degraded': 'Redis degradado (modo memoria)',

  'ov.decisions': 'Decisiones / min',
  'ov.logLines': 'Líneas de log de seguridad / min',
  'ov.activeIps': 'IPs activas (5 min)',
  'ov.bans': 'Bloqueos activos',
  'ov.wouldBans': 'Bloquearía (AUDIT)',
  'ov.suspicious': 'Sospechosas (60 min)',
  'ov.sg403': '403 de SmartGuard',
  'ov.sg429': '429 de SmartGuard',
  'ov.nginx403': '403 de Nginx',
  'ov.nginx429': '429 de Nginx',
  'ov.phpAvoided': 'Peticiones PHP evitadas',
  'ov.wouldBlock': 'Bloquearía / limitaría',
  'ov.topPaths': 'Rutas de ataque más frecuentes',
  'ov.topIps': 'IPs con más puntos',
  'ov.topRules': 'Reglas más disparadas',
  'ov.path': 'Ruta',
  'ov.hits': 'Veces',
  'ov.points': 'Puntos',
  'ov.rule': 'Regla',

  'mg.check.title': 'Consultar una IP, dominio o sitio',
  'mg.check.placeholder': 'IP, CIDR, dominio, *.dominio o https://sitio…',
  'mg.check.button': 'Consultar',
  'mg.check.help': 'Indica si el valor ya está en la lista blanca (y en cuál) o si está bloqueado.',
  'mg.status.notListed': '{value} no está en ninguna lista.',
  'mg.status.allowlisted': '{value} ya está en la lista blanca:',
  'mg.status.blocked': '{value} está BLOQUEADA {until}.',
  'mg.status.auditBlocked': 'En AUDIT se bloquearía {until}.',
  'mg.status.fpBans': '{count} bloqueo(s) por huella IP + navegador.',
  'mg.status.score': 'Score actual: {score}',
  'mg.status.cloudflare': 'Es una IP de Cloudflare: nunca la bloquees (bloquearías a todos tus visitantes).',
  'mg.match': '{list} · {source} · {how}{detail}',

  'mg.allow.title': 'Permitir un cliente (quién se conecta)',
  'mg.allow.help': 'IP, CIDR, dominio exacto (se resuelve a sus IPs) o *.dominio (verificado por DNS inverso). Permitir una IP también la desbloquea.',
  'mg.allow.value': 'IP, CIDR, dominio o *.dominio',
  'mg.allow.list': 'Lista',
  'mg.allow.note': 'Nota (opcional)',
  'mg.allow.ttl': 'Caduca',
  'mg.allow.submit': 'Permitir cliente',
  'mg.allow.done': '{value} añadido a {list}.',

  'mg.host.title': 'Permitir un sitio o subdominio (destino)',
  'mg.host.help': 'SmartGuard no puntuará las peticiones a este sitio. Acepta dominio, *.dominio o una URL (https://api.ejemplo.com/ruta).',
  'mg.host.value': 'dominio, *.dominio o URL',
  'mg.host.submit': 'Permitir sitio',
  'mg.host.done': 'Sitio {value} exento.',

  'mg.block.title': 'Bloquear una IP',
  'mg.block.help': 'Bloqueo manual. Se aplica al momento (también en modo AUDIT).',
  'mg.block.ip': 'IPv4 o IPv6',
  'mg.block.duration': 'Duración',
  'mg.block.reason': 'Motivo (opcional)',
  'mg.block.submit': 'Bloquear IP',
  'mg.block.done': '{ip} bloqueada hasta {until}.',

  'mg.unblock.title': 'Desbloquear una IP',
  'mg.unblock.help': 'Quita el bloqueo de la IP, los bloqueos por huella, nftables y Cloudflare. Por defecto también resetea su score para que no se vuelva a bloquear al instante.',
  'mg.unblock.keepScore': 'Conservar score e historial',
  'mg.unblock.submit': 'Desbloquear IP',
  'mg.unblock.done': '{ip} desbloqueada ({fp} bloqueo(s) por huella eliminados).',
  'mg.unblock.notBlocked': '{ip} no estaba bloqueada. Score reseteado: {reset}.',

  'ttl.never': 'Nunca',
  'dur.15m': '15 minutos',
  'dur.1h': '1 hora',
  'dur.6h': '6 horas',
  'dur.24h': '24 horas',
  'dur.7d': '7 días',
  'dur.30d': '30 días',
  'dur.365d': '1 año',

  'list.ADMIN_ALLOWLIST': 'IPs de administración',
  'list.SERVICE_ALLOWLIST': 'Servicios',
  'list.TRUSTED_NETWORK': 'Redes de confianza',
  'list.ALLOW_HOSTS': 'Sitios exentos',
  'source.env': 'archivo .env',
  'source.dynamic': 'dashboard / API',
  'source.builtin': 'integrada',
  'how.exact': 'coincidencia exacta',
  'how.cidr': 'dentro del rango {value}',
  'how.domain-resolved': 'IP del dominio {value}',
  'how.subdomain-verified': 'subdominio verificado de {value}',
  'how.domain-pattern': 'cubierto por {value}',
  'how.host': 'sitio exento {value}',

  'bl.title': 'IPs bloqueadas',
  'bl.showAudit': 'Ver bloqueos simulados (AUDIT)',
  'bl.ip': 'IP / clave',
  'bl.score': 'Score',
  'bl.reason': 'Motivo',
  'bl.scope': 'Alcance',
  'bl.source': 'Origen',
  'bl.count': 'Veces',
  'bl.created': 'Creado',
  'bl.expires': 'Caduca',
  'bl.mode': 'Modo',
  'bl.action': 'Acción',
  'bl.confirmUnblock': '¿Desbloquear {ip}?',

  'al.title': 'Lista blanca',
  'al.value': 'Valor',
  'al.list': 'Lista',
  'al.target': 'Aplica a',
  'al.target.client': 'cliente',
  'al.target.host': 'sitio',
  'al.origin': 'Origen / nota',
  'al.resolved': 'IPs resueltas',
  'al.editEnv': 'editar .env',
  'al.confirmRemove': '¿Quitar {value} de la lista blanca?',
  'al.removed': '{value} quitado de la lista blanca.',

  'ev.title': 'Eventos de seguridad recientes',
  'ev.time': 'Hora',
  'ev.action': 'Acción',
  'ev.country': 'País',
  'ev.host': 'Host',
  'ev.method': 'Método',
  'ev.uri': 'URI',
  'ev.status': 'Estado',
  'ev.category': 'Categoría',
  'ev.delta': 'Δ',
  'ev.reason': 'Motivo',

  'inspect.title': '¿Por qué? — {ip}',
  'inspect.close': 'Cerrar',

  'err.generic': 'Error {status}: {message}',
  'err.network': 'No se puede contactar con SmartGuard. ¿Está el servicio activo y el túnel SSH abierto?',
  'err.UNAUTHORIZED': 'Token de administrador ausente o incorrecto.',
  'err.RATE_LIMITED': 'Demasiadas peticiones. Espera un minuto.',
  'err.VALIDATION': 'Campo "{field}" no válido: {reason}',
  'err.INVALID_VALUE': 'Valor no válido. Usa una IP, CIDR, dominio, *.dominio o URL de un sitio.',
  'err.INVALID_IP': 'Dirección IP no válida.',
  'err.ALREADY_ALLOWLISTED': '{value} ya está en la lista blanca: {lists}.',
  'err.ALREADY_COVERED': '{value} ya está cubierto por: {lists}.',
  'err.IP_ALLOWLISTED': '{ip} está en la lista blanca ({lists}). Quítala de la lista blanca antes de bloquearla.',
  'err.ALREADY_BANNED': '{ip} ya está bloqueada hasta {until} ({reason}).',
  'err.CLOUDFLARE_IP': '{ip} es una IP de Cloudflare. Bloquearla bloquearía a todos tus visitantes.',
  'err.NOT_IN_ALLOWLIST': '{value} no está en la lista blanca.',
  'err.STATIC_ENTRY': '{value} está definido en el archivo .env ({lists}). Edita /etc/smartguard/smartguard.env y reinicia SmartGuard.',
  'err.HOST_REQUIRES_DOMAIN': 'Un sitio exento debe ser un dominio, *.dominio o URL, no una IP.',
  'err.RELOAD_REJECTED': 'Recarga de reglas rechazada: {error}',
};

const DICTS: Record<Lang, Dict> = { en: EN, es: ES };
const STORAGE_KEY = 'sg_lang';

function readStoredLang(): Lang {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === 'es' || v === 'en' ? v : 'en';
  } catch {
    return 'en';
  }
}

@Injectable({ providedIn: 'root' })
export class I18n {
  /** Inglés por defecto */
  readonly lang = signal<Lang>(readStoredLang());

  constructor() {
    document.documentElement.lang = this.lang();
  }

  set(lang: Lang): void {
    this.lang.set(lang);
    document.documentElement.lang = lang;
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      /* navegador sin almacenamiento: solo esta sesión */
    }
  }

  t(key: string, params: Record<string, unknown> = {}): string {
    const dict = DICTS[this.lang()];
    const text = dict[key] ?? EN[key] ?? key;
    return text.replace(/\{(\w+)\}/g, (_m, p: string) => (params[p] === undefined || params[p] === null ? '' : String(params[p])));
  }

  /** Fecha/hora en el idioma activo */
  date(ms: number | undefined | null): string {
    if (!ms) return '';
    return new Date(ms).toLocaleString(this.lang() === 'es' ? 'es-ES' : 'en-US');
  }

  time(ms: number): string {
    return new Date(ms).toLocaleTimeString(this.lang() === 'es' ? 'es-ES' : 'en-US');
  }
}

/** {{ 'key' | t }}  ·  {{ 'key' | t: { ip: x } }} — impuro para reaccionar al cambio de idioma. */
@Pipe({ name: 't', pure: false })
export class TPipe implements PipeTransform {
  private readonly i18n = inject(I18n);
  transform(key: string, params?: Record<string, unknown>): string {
    return this.i18n.t(key, params ?? {});
  }
}
