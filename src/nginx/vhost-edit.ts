/**
 * Edición de vhosts de Nginx para "smartguard protect / unprotect": inserta (o quita) los include
 * de SmartGuard leyendo la estructura del archivo, sin tocar nada más.
 *
 * Dónde se inserta:
 *  - server.conf + auth.conf → en cada server{} de ENTRADA (el que escucha en 80/443), tras su
 *    server_name. No en los que solo redirigen ni en los internos (p. ej. el backend 8080 que
 *    CloudPanel pone detrás de Varnish: ahí la IP del cliente ya es 127.0.0.1).
 *  - auth-php.conf → en las location de esos server{} que envían la petición a PHP: las que tienen
 *    fastcgi_pass, o proxy_pass hacia un server{} interno del mismo archivo.
 * Los aplicativos detrás de proxy_pass a otro puerto solo reciben los dos include de nivel server.
 */

const SNIPPET_DIR = '/etc/nginx/smartguard';
const MARK = '# [SmartGuard] smartguard protect';

interface Directive {
  name: string;
  args: string[];
  /** índice del primer carácter de la directiva y del ";" final */
  start: number;
  end: number;
}

interface Block {
  name: string;
  args: string[];
  /** índice del primer carácter de la cabecera, de "{" y de "}" */
  start: number;
  open: number;
  close: number;
  children: Block[];
  directives: Directive[];
}

/** Lee la estructura de bloques y directivas. Ignora comentarios, comillas y variables ${...}. */
export function parseNginx(text: string): Block {
  const root: Block = { name: '', args: [], start: 0, open: -1, close: text.length, children: [], directives: [] };
  const stack: Block[] = [root];
  let tokens: string[] = [];
  let tokenStart = -1;
  let cur = '';
  let headStart = -1;
  const endToken = () => {
    if (cur) {
      if (tokens.length === 0) headStart = tokenStart;
      tokens.push(cur);
      cur = '';
    }
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '#' && !cur) {
      while (i < text.length && text[i] !== '\n') i++;
      continue;
    }
    if (c === '"' || c === "'") {
      if (!cur) tokenStart = i;
      cur += c;
      for (i++; i < text.length && text[i] !== c; i++) {
        if (text[i] === '\\') cur += text[i++];
        cur += text[i] ?? '';
      }
      cur += c;
      continue;
    }
    if (c === '$' && text[i + 1] === '{') {
      if (!cur) tokenStart = i;
      const close = text.indexOf('}', i);
      const stop = close === -1 ? text.length - 1 : close;
      cur += text.slice(i, stop + 1);
      i = stop;
      continue;
    }
    if (/\s/.test(c)) {
      endToken();
      continue;
    }
    if (c === ';') {
      endToken();
      if (tokens.length) stack[stack.length - 1]!.directives.push({ name: tokens[0]!, args: tokens.slice(1), start: headStart, end: i });
      tokens = [];
      continue;
    }
    if (c === '{') {
      endToken();
      const b: Block = { name: tokens[0] ?? '', args: tokens.slice(1), start: tokens.length ? headStart : i, open: i, close: -1, children: [], directives: [] };
      stack[stack.length - 1]!.children.push(b);
      stack.push(b);
      tokens = [];
      continue;
    }
    if (c === '}') {
      endToken();
      tokens = [];
      if (stack.length > 1) stack.pop()!.close = i;
      continue;
    }
    if (!cur) tokenStart = i;
    cur += c;
  }
  return root;
}

function allBlocks(b: Block, name: string, out: Block[] = []): Block[] {
  for (const c of b.children) {
    if (c.name === name) out.push(c);
    allBlocks(c, name, out);
  }
  return out;
}

function hasInclude(b: Block, file: string): boolean {
  return b.directives.some((d) => d.name === 'include' && d.args[0] === `${SNIPPET_DIR}/${file}`);
}

/** Puerto de una directiva listen ("443 ssl", "[::]:8080", "127.0.0.1:9000") y si es solo local. */
function listenInfo(d: Directive): { port: number; local: boolean } {
  const addr = d.args[0] ?? '80';
  const m = /(?:^|:)(\d+)$/.exec(addr);
  return { port: m ? Number(m[1]) : 80, local: /^(127\.|localhost|\[::1\])/.test(addr) };
}

/** Server interno: todos sus listen son locales o del puerto 8080 (backend tras Varnish/proxy). */
function isBackend(server: Block): boolean {
  const listens = server.directives.filter((d) => d.name === 'listen').map(listenInfo);
  return listens.length > 0 && listens.every((l) => l.local || l.port === 8080);
}

function lineStart(text: string, i: number): number {
  return text.lastIndexOf('\n', i - 1) + 1;
}
function indentAt(text: string, i: number): string {
  return /^[ \t]*/.exec(text.slice(lineStart(text, i)))![0];
}
/** Posición justo después del salto de línea que sigue a `i` (o el final del texto). */
function afterLine(text: string, i: number): number {
  const nl = text.indexOf('\n', i);
  return nl === -1 ? text.length : nl + 1;
}

export interface VhostChange {
  /** línea (1…n) del archivo ORIGINAL tras la que se inserta, o que se elimina */
  line: number;
  text: string;
}

export interface VhostEdit {
  text: string;
  changes: VhostChange[];
  warnings: string[];
  /** cómo queda el sitio: reglas de Nginx y/o decisión de SmartGuard */
  rules: boolean;
  decision: boolean;
}

/** Devuelve el vhost con los include de SmartGuard insertados. Idempotente. */
export function protectVhost(text: string): VhostEdit {
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const root = parseNginx(text);
  const servers = root.children.filter((b) => b.name === 'server');
  const warnings: string[] = [];
  const inserts: { pos: number; text: string; shown: string[] }[] = [];
  const backends = servers.filter(isBackend);
  const backendPorts = new Set(backends.flatMap((s) => s.directives.filter((d) => d.name === 'listen').map((d) => listenInfo(d).port)));
  let rules = false;
  let decision = false;

  /** Inserta una o varias directivas, cada una en su línea, en `pos` (inicio de una línea). */
  const insertLines = (pos: number, indent: string, stmts: string[]) => {
    if (stmts.length) inserts.push({ pos, text: stmts.map((s) => `${indent}${s}   ${MARK}${eol}`).join(''), shown: stmts });
  };

  for (const server of servers) {
    if (backends.includes(server) && backends.length < servers.length) continue;
    const locations = allBlocks(server, 'location');
    // solo redirige (sin locations y con return): no sirve contenido, no hay nada que proteger
    if (locations.length === 0 && server.directives.some((d) => d.name === 'return')) continue;

    const anchor = server.directives.find((d) => d.name === 'server_name');
    const pos = anchor ? afterLine(text, anchor.end) : afterLine(text, server.open);
    const indent = anchor ? indentAt(text, anchor.start) : `${indentAt(text, server.start)}  `;
    insertLines(pos, indent, ['server.conf', 'auth.conf'].filter((f) => !hasInclude(server, f)).map((f) => `include ${SNIPPET_DIR}/${f};`));
    rules = true;

    for (const loc of locations) {
      const toPhp =
        loc.directives.some((d) => d.name === 'fastcgi_pass') ||
        loc.directives.some((d) => d.name === 'proxy_pass' && [...backendPorts].some((p) => new RegExp(`//(127\\.0\\.0\\.1|localhost):${p}\\b`).test(d.args[0] ?? '')));
      if (!toPhp) continue;
      decision = true;
      if (hasInclude(loc, 'auth-php.conf')) continue;
      const first = [...loc.directives.map((d) => d.start), ...loc.children.map((c) => c.start)].sort((a, b) => a - b)[0];
      const stmt = `include ${SNIPPET_DIR}/auth-php.conf;`;
      if (text.indexOf('\n', loc.open) === -1 || (first !== undefined && first < text.indexOf('\n', loc.open))) {
        // location escrita en una sola línea: se inserta tras la llave
        inserts.push({ pos: loc.open + 1, text: ` ${stmt}`, shown: [stmt] });
      } else {
        insertLines(afterLine(text, loc.open), first !== undefined ? indentAt(text, first) : `${indentAt(text, loc.start)}  `, [stmt]);
      }
    }
  }
  if (!rules) warnings.push('no hay ningún server{} de entrada con contenido: no se cambia nada');
  else if (!decision) warnings.push('no hay ninguna location que envíe a PHP: solo se añaden reglas y límites de Nginx (quedará como Parcial)');

  const lineOf = (pos: number) => text.slice(0, pos).split('\n').length - (pos > 0 && text[pos - 1] === '\n' ? 1 : 0);
  // de atrás hacia delante para que las posiciones sigan siendo válidas
  let out = text;
  for (const ins of [...inserts].sort((a, b) => b.pos - a.pos)) out = out.slice(0, ins.pos) + ins.text + out.slice(ins.pos);
  const changes = [...inserts].sort((a, b) => a.pos - b.pos).flatMap((i) => i.shown.map((s) => ({ line: lineOf(i.pos), text: `+ ${s}` })));
  return { text: out, changes, warnings, rules, decision };
}

/** Quita los include de SmartGuard (server.conf, auth.conf, auth-php.conf) de un vhost. */
export function unprotectVhost(text: string): VhostEdit {
  const root = parseNginx(text);
  const targets: Directive[] = [];
  const walk = (b: Block) => {
    for (const d of b.directives) {
      if (d.name === 'include' && /smartguard\/(server|auth|auth-php)\.conf$/.test(d.args[0] ?? '')) targets.push(d);
    }
    b.children.forEach(walk);
  };
  walk(root);
  const changes: VhostChange[] = [];
  let out = text;
  for (const d of [...targets].sort((a, b) => b.start - a.start)) {
    const ls = lineStart(out, d.start);
    const le = afterLine(out, d.end);
    const line = out.slice(ls, le);
    const rest = (line.slice(0, d.start - ls) + line.slice(d.end + 1 - ls)).replace(new RegExp(`\\s*${MARK.replace(/[[\]]/g, '\\$&')}`), '');
    changes.unshift({ line: text.slice(0, d.start).split('\n').length, text: `- include ${d.args[0]};` });
    // si en la línea solo quedaba el include (y quizá un comentario), se quita entera
    out = /^\s*(#.*)?\r?\n?$/.test(rest) ? out.slice(0, ls) + out.slice(le) : out.slice(0, ls) + rest + out.slice(le);
  }
  return { text: out, changes, warnings: targets.length ? [] : ['el vhost no tiene ningún include de SmartGuard'], rules: false, decision: false };
}
