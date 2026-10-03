/**
 * Normalización segura de URIs y redacción de datos sensibles.
 * Nada aquí hace I/O ni usa regex costosas: se ejecuta en cada decisión.
 */

export const MAX_PATH_LEN = 2048;
export const MAX_QUERY_LEN = 2048;
export const MAX_UA_LEN = 512;

export interface AnalyzedUri {
  /** ruta decodificada y normalizada (sin segmentos . y .., sin // duplicadas) */
  path: string;
  /** ruta cruda tal y como llegó (sin query) */
  rawPath: string;
  /** query cruda (sin "?") */
  query: string;
  /** query decodificada una vez + una segunda vez si seguía codificada (anti-evasión) */
  decodedQuery: string;
  malformed: boolean;
  tooLong: boolean;
  dotSegments: boolean;
  nullByte: boolean;
}

function safeDecode(s: string): { value: string; malformed: boolean } {
  if (!s.includes('%') && !s.includes('+')) return { value: s, malformed: false };
  try {
    return { value: decodeURIComponent(s.replace(/\+/g, ' ')), malformed: false };
  } catch {
    // Secuencias % inválidas: se decodifica lo que se pueda byte a byte.
    const value = s.replace(/%([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
    return { value, malformed: true };
  }
}

export function analyzeUri(rawUri: string): AnalyzedUri {
  let uri = rawUri || '/';
  let tooLong = false;
  if (uri.length > MAX_PATH_LEN + MAX_QUERY_LEN) {
    uri = uri.slice(0, MAX_PATH_LEN + MAX_QUERY_LEN);
    tooLong = true;
  }
  const qi = uri.indexOf('?');
  let rawPath = qi >= 0 ? uri.slice(0, qi) : uri;
  let query = qi >= 0 ? uri.slice(qi + 1) : '';
  if (rawPath.length > MAX_PATH_LEN) {
    rawPath = rawPath.slice(0, MAX_PATH_LEN);
    tooLong = true;
  }
  if (query.length > MAX_QUERY_LEN) {
    query = query.slice(0, MAX_QUERY_LEN);
    tooLong = true;
  }

  // Ruta: decodificar sin convertir "+" (en la ruta "+" es literal)
  let malformed = false;
  let decodedPath: string;
  try {
    decodedPath = rawPath.includes('%') ? decodeURIComponent(rawPath) : rawPath;
  } catch {
    malformed = true;
    decodedPath = rawPath.replace(/%([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
  }
  const nullByte = decodedPath.includes('\u0000') || query.toLowerCase().includes('%00');
  decodedPath = decodedPath.replace(/\u0000/g, '').replace(/\\/g, '/');

  // Resolver segmentos de punto y barras duplicadas
  const out: string[] = [];
  let dotSegments = false;
  for (const seg of decodedPath.split('/')) {
    if (seg === '' || seg === '.') {
      if (seg === '.') dotSegments = true;
      continue;
    }
    if (seg === '..') {
      dotSegments = true;
      out.pop();
      continue;
    }
    out.push(seg);
  }
  let path = '/' + out.join('/');
  if (decodedPath.endsWith('/') && path !== '/') path += '/';

  const q1 = safeDecode(query);
  let decodedQuery = q1.value;
  malformed = malformed || q1.malformed;
  if (/%[0-9a-fA-F]{2}/.test(decodedQuery)) {
    const q2 = safeDecode(decodedQuery);
    decodedQuery = `${decodedQuery} ${q2.value}`;
  }

  return { path, rawPath, query, decodedQuery, malformed, tooLong, dotSegments, nullByte };
}

const SENSITIVE_PARAM = /pass|pwd|token|secret|key|auth|session|sess|nonce|email|mail|phone|tel|card|cvv|cvc|iban|billing|shipping|address|name|user|login|otp|code|hash|sig|jwt/i;

/**
 * Redacta parámetros sensibles de una query string (punto 18 y 67).
 * Devuelve como máximo `maxLen` caracteres.
 */
export function redactQuery(query: string, maxLen = 256): string {
  if (!query) return '';
  const parts = query.split('&').slice(0, 30).map((pair) => {
    const eq = pair.indexOf('=');
    const k = eq >= 0 ? pair.slice(0, eq) : pair;
    if (eq < 0) return k.slice(0, 64);
    return SENSITIVE_PARAM.test(k) ? `${k.slice(0, 64)}=[REDACTED]` : `${k.slice(0, 64)}=${pair.slice(eq + 1, eq + 1 + 96)}`;
  });
  const s = parts.join('&');
  return s.length > maxLen ? `${s.slice(0, maxLen)}…` : s;
}

/** Limpia texto para logs: sin caracteres de control, truncado. */
export function cleanText(s: string | undefined | null, maxLen: number): string {
  if (!s) return '';
  // eslint-disable-next-line no-control-regex
  const c = s.replace(/[\u0000-\u001f\u007f]/g, ' ');
  return c.length > maxLen ? c.slice(0, maxLen) : c;
}

/** Host seguro: minúsculas, sin puerto, solo [a-z0-9.-]. */
export function normalizeHost(h: string | undefined | null): string {
  if (!h) return '';
  let s = h.trim().toLowerCase();
  if (s.startsWith('[')) return ''; // literal IPv6 como host: no es un sitio configurado
  const colon = s.indexOf(':');
  if (colon >= 0) s = s.slice(0, colon);
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (s.length === 0 || s.length > 253 || !/^[a-z0-9.-]+$/.test(s)) return '';
  return s;
}

/** Parse "15m", "1h", "2d", "3600" → segundos. */
export function parseDuration(input: string | number | undefined, fallbackSec: number): number {
  if (input === undefined || input === null || input === '') return fallbackSec;
  if (typeof input === 'number') return Number.isFinite(input) && input > 0 ? Math.floor(input) : fallbackSec;
  const m = /^\s*(\d+)\s*([smhdw]?)\s*$/i.exec(input);
  if (!m) return fallbackSec;
  const n = parseInt(m[1]!, 10);
  const mult: Record<string, number> = { '': 1, s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
  const v = n * (mult[m[2]!.toLowerCase()] ?? 1);
  return v > 0 ? v : fallbackSec;
}

export function formatDuration(sec: number): string {
  if (sec % 86400 === 0) return `${sec / 86400}d`;
  if (sec % 3600 === 0) return `${sec / 3600}h`;
  if (sec % 60 === 0) return `${sec / 60}m`;
  return `${sec}s`;
}
