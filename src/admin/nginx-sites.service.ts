import { Injectable } from '@nestjs/common';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { AllowlistService } from '../whitelist/allowlist.service';

/** Qué hace SmartGuard en un sitio de Nginx, según los include de su vhost. */
export interface ParsedVhost {
  /** dominios de sus server_name (sin duplicados) */
  names: string[];
  /** php = WordPress u otra app PHP (fastcgi) · proxy = aplicativo detrás de proxy_pass · static */
  kind: 'php' | 'proxy' | 'static';
  /** server.conf: reglas Nginx nuevas, límites por endpoint y log de seguridad */
  rules: boolean;
  /** auth.conf + auth-php.conf: cada petición dinámica consulta la decisión de SmartGuard */
  decision: boolean;
  /** static-log.conf: se registran los 4xx de archivos estáticos */
  staticLog: boolean;
}

export interface NginxSite extends ParsedVhost {
  file: string;
  /** full = reglas + decisión · partial = solo una de las dos · none */
  status: 'full' | 'partial' | 'none';
  /** todos sus dominios están en ALLOW_HOSTS: SmartGuard no los puntúa aunque el vhost lo incluya */
  exempt: boolean;
}

/**
 * Carpetas de vhosts. Cada una tiene dos rutas: la vista de solo lectura que monta systemd
 * (BindReadOnlyPaths de smartguard.service; /etc/nginx no es accesible para el usuario del
 * servicio) y la ruta real, por si el servicio corre sin esa restricción.
 */
const SITE_DIRS: string[][] = [
  ['/var/lib/smartguard/nginx-view/sites-enabled', '/etc/nginx/sites-enabled'],
  ['/var/lib/smartguard/nginx-view/conf.d', '/etc/nginx/conf.d'],
];
/** archivos propios de SmartGuard (contexto http), no son sitios */
const OWN_FILE = /^(\d+-)?smartguard\.conf$/;
const MAX_FILE_BYTES = 512 * 1024;
const TTL_MS = 60_000;

/** Lee un vhost de Nginx. Los comentarios se descartan: un include comentado no protege nada. */
export function parseVhost(text: string): ParsedVhost {
  const code = text
    .split('\n')
    .map((l) => l.replace(/(^|\s)#.*$/, ''))
    .join('\n');
  const names = new Set<string>();
  for (const m of code.matchAll(/\bserver_name\s+([^;]+);/g)) {
    for (const n of m[1]!.split(/\s+/)) if (n && n !== '_') names.add(n.toLowerCase());
  }
  const has = (file: string) => new RegExp(`\\binclude\\s+[^;]*smartguard/${file}\\s*;`).test(code);
  return {
    names: [...names],
    kind: /\bfastcgi_pass\s/.test(code) ? 'php' : /\bproxy_pass\s/.test(code) ? 'proxy' : 'static',
    rules: has('server\\.conf'),
    decision: has('auth\\.conf') && has('auth-php\\.conf'),
    staticLog: has('static-log\\.conf'),
  };
}

/**
 * Sitios que Nginx tiene configurados y cuáles pasan por SmartGuard. Solo lectura de los vhosts;
 * si el servicio no tiene permiso para leerlos, lo indica en lugar de adivinar.
 */
@Injectable()
export class NginxSitesService {
  private cache: { at: number; value: { readable: boolean; dirs: string[]; items: NginxSite[] } } | null = null;

  constructor(private readonly allowlist: AllowlistService) {}

  async list(dirs: string[][] = SITE_DIRS): Promise<{ readable: boolean; dirs: string[]; items: NginxSite[] }> {
    if (this.cache && Date.now() - this.cache.at < TTL_MS && dirs === SITE_DIRS) return this.withExempt(this.cache.value);
    const items: NginxSite[] = [];
    let found = 0;
    let unreadable = 0;
    const denied: string[] = [];
    for (const candidates of dirs) {
      // se usa la primera ruta que se pueda listar y tenga archivos (la vista montada, si existe)
      let dir = '';
      let files: string[] = [];
      for (const candidate of candidates) {
        try {
          const all = await fs.readdir(candidate);
          if (all.length === 0) continue; // punto de montaje vacío: la vista no está montada
          dir = candidate;
          files = all.filter((f) => f.endsWith('.conf') && !OWN_FILE.test(f)).sort();
          break;
        } catch (e) {
          // una carpeta que no existe es normal (conf.d); una que existe pero no se puede listar, no
          if ((e as NodeJS.ErrnoException).code !== 'ENOENT') denied.push(candidate);
        }
      }
      if (!dir) continue;
      for (const file of files) {
        found++;
        let text: string;
        try {
          const abs = path.join(dir, file);
          if ((await fs.stat(abs)).size > MAX_FILE_BYTES) continue;
          text = await fs.readFile(abs, 'utf8');
        } catch {
          unreadable++;
          continue;
        }
        const v = parseVhost(text);
        if (v.names.length === 0) continue; // no define ningún sitio (p. ej. solo maps o upstreams)
        items.push({
          file,
          ...v,
          status: v.rules && v.decision ? 'full' : v.rules || v.decision ? 'partial' : 'none',
          exempt: false,
        });
      }
    }
    // primero los protegidos; dentro de cada grupo, por nombre
    const rank = { full: 0, partial: 1, none: 2 };
    items.sort((a, b) => rank[a.status] - rank[b.status] || a.names[0]!.localeCompare(b.names[0]!));
    // sin acceso = no se encontró ningún vhost y alguna carpeta no se pudo listar, o no se pudo leer ninguno
    const readable = found === 0 ? denied.length === 0 : unreadable < found;
    const value = { readable, dirs: readable ? dirs.flat() : denied.length ? denied : dirs.flat(), items };
    if (dirs === SITE_DIRS) this.cache = { at: Date.now(), value };
    return this.withExempt(value);
  }

  /**
   * "Exento" se calcula en cada consulta y no se guarda con la lectura de los vhosts: la lista
   * blanca cambia desde el panel y, tras un reinicio, puede tardar unos segundos en cargarse.
   */
  private withExempt<T extends { items: NginxSite[] }>(value: T): T {
    return { ...value, items: value.items.map((s) => ({ ...s, exempt: s.names.every((n) => this.allowlist.hostAllowed(n)) })) };
  }
}
