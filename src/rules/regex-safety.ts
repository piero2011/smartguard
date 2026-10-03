/**
 * Protección anti-ReDoS para reglas configurables (punto 30).
 *
 * Node no tiene timeout para RegExp, así que se aplican tres barreras al CARGAR las reglas
 * (nunca por petición):
 *  1. Análisis estático: se rechazan cuantificadores anidados ((a+)+, (.*)*), alternancias dentro de
 *     grupos con cuantificador ilimitado ((a|ab)+), backreferences y patrones demasiado largos.
 *  2. Prueba de tiempo con entradas adversariales.
 *  3. En tiempo de ejecución las entradas se truncan (ruta/query 2048, UA 512).
 */

export const MAX_PATTERN_LEN = 600;
// Una regex catastrófica tarda segundos con 4000 caracteres; 50 ms deja margen a servidores cargados.
const MAX_TEST_MS = 50;

export class UnsafeRegexError extends Error {}

interface Frame {
  unbounded: boolean;
  alternation: boolean;
}

function readQuantifier(p: string, i: number): { len: number; unbounded: boolean } | null {
  const c = p[i];
  if (c === '*' || c === '+') return { len: p[i + 1] === '?' ? 2 : 1, unbounded: true };
  if (c === '?') return { len: p[i + 1] === '?' ? 2 : 1, unbounded: false };
  if (c === '{') {
    const m = /^\{(\d+)(,(\d*))?\}\??/.exec(p.slice(i));
    if (!m) return null;
    const hasComma = m[2] !== undefined;
    const max = m[3] === undefined || m[3] === '' ? Infinity : parseInt(m[3], 10);
    const unbounded = hasComma && (max === Infinity || max > 16);
    return { len: m[0].length, unbounded };
  }
  return null;
}

/** Lanza UnsafeRegexError si el patrón es potencialmente catastrófico. */
export function assertStaticallySafe(pattern: string): void {
  if (pattern.length === 0) throw new UnsafeRegexError('patrón vacío');
  if (pattern.length > MAX_PATTERN_LEN) throw new UnsafeRegexError(`patrón demasiado largo (> ${MAX_PATTERN_LEN})`);
  if (/\\[1-9]|\\k</.test(pattern)) throw new UnsafeRegexError('backreferences no permitidas');

  const stack: Frame[] = [{ unbounded: false, alternation: false }];
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i]!;
    if (c === '\\') {
      i += 2;
      const q = readQuantifier(pattern, i);
      if (q) {
        if (q.unbounded) stack[stack.length - 1]!.unbounded = true;
        i += q.len;
      }
      continue;
    }
    if (c === '[') {
      // saltar clase de caracteres
      i++;
      if (pattern[i] === '^') i++;
      if (pattern[i] === ']') i++;
      while (i < pattern.length && pattern[i] !== ']') {
        if (pattern[i] === '\\') i++;
        i++;
      }
      i++;
      const q = readQuantifier(pattern, i);
      if (q) {
        if (q.unbounded) stack[stack.length - 1]!.unbounded = true;
        i += q.len;
      }
      continue;
    }
    if (c === '(') {
      stack.push({ unbounded: false, alternation: false });
      i++;
      if (pattern[i] === '?') {
        // (?: (?= (?! (?<= (?<! (?<name>
        i++;
        if (pattern[i] === '<' && pattern[i + 1] !== '=' && pattern[i + 1] !== '!') {
          const close = pattern.indexOf('>', i);
          if (close < 0) throw new UnsafeRegexError('grupo con nombre mal formado');
          i = close + 1;
        } else if (pattern[i] === '<') {
          i += 2;
        } else {
          i++;
        }
      }
      continue;
    }
    if (c === ')') {
      const frame = stack.pop();
      if (!frame || stack.length === 0) throw new UnsafeRegexError('paréntesis desbalanceados');
      i++;
      const q = readQuantifier(pattern, i);
      if (q) {
        if (q.unbounded && frame.unbounded) {
          throw new UnsafeRegexError('cuantificadores anidados (p. ej. (a+)+) no permitidos');
        }
        if (q.unbounded && frame.alternation) {
          throw new UnsafeRegexError('alternancia dentro de grupo con cuantificador ilimitado (p. ej. (a|b)+) no permitida; usa una clase [ab]+');
        }
        i += q.len;
      }
      const parent = stack[stack.length - 1]!;
      parent.unbounded = parent.unbounded || frame.unbounded || (q?.unbounded ?? false);
      continue;
    }
    if (c === '|') {
      stack[stack.length - 1]!.alternation = true;
      i++;
      continue;
    }
    i++;
    const q = readQuantifier(pattern, i);
    if (q) {
      if (q.unbounded) stack[stack.length - 1]!.unbounded = true;
      i += q.len;
    }
  }
  if (stack.length !== 1) throw new UnsafeRegexError('paréntesis desbalanceados');
}

const ADVERSARIAL: string[] = [
  'a'.repeat(4000) + '!',
  '/'.repeat(2000) + 'x',
  '.'.repeat(2000) + '!',
  '%2e'.repeat(700) + '%',
  ('/wp-content/plugins/' + 'a'.repeat(40)).repeat(40),
  ' '.repeat(2000) + 'x',
  ('a/' + 'b.'.repeat(10)).repeat(150),
  '='.repeat(1000) + '&'.repeat(1000),
];

/** Compila una regex tras validarla. Solo flags "i" permitido. */
export function compileSafeRegex(pattern: string, flags = ''): RegExp {
  if (!/^i?$/.test(flags)) throw new UnsafeRegexError(`flags no permitidos: "${flags}" (solo "i")`);
  assertStaticallySafe(pattern);
  let re: RegExp;
  try {
    re = new RegExp(pattern, flags);
  } catch (e) {
    throw new UnsafeRegexError(`regex inválida: ${(e as Error).message}`);
  }
  for (const input of ADVERSARIAL) {
    // mínimo de 3 mediciones: una pausa de GC o un servidor cargado no deben rechazar una regla segura
    let best = Infinity;
    for (let attempt = 0; attempt < 3 && best > MAX_TEST_MS; attempt++) {
      const t0 = process.hrtime.bigint();
      re.test(input);
      best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6);
    }
    if (best > MAX_TEST_MS) throw new UnsafeRegexError(`regex demasiado lenta con entrada adversarial (${best.toFixed(1)} ms)`);
  }
  return re;
}
