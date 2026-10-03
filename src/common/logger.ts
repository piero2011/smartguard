import { LoggerService } from '@nestjs/common';

/**
 * Logger JSON a stdout (journald lo captura y rota). Sin dependencias.
 * Nunca registrar cookies, Authorization, tokens ni cuerpos de petición:
 * los campos con nombres sensibles se redactan por defensa en profundidad.
 */

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 } as const;
export type LogLevel = keyof typeof LEVELS;

const SENSITIVE_KEY = /pass|token|secret|authorization|cookie|api[_-]?key|x-smartguard-key/i;

function redact(value: unknown, depth = 0): unknown {
  if (depth > 4 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE_KEY.test(k) ? '[REDACTED]' : redact(v, depth + 1);
  }
  return out;
}

export class JsonLogger implements LoggerService {
  private threshold: number;

  constructor(level: string = 'info') {
    this.threshold = LEVELS[(level as LogLevel)] ?? LEVELS.info;
  }

  setLevel(level: string): void {
    this.threshold = LEVELS[(level as LogLevel)] ?? LEVELS.info;
  }

  isDebug(): boolean {
    return this.threshold >= LEVELS.debug;
  }

  private write(level: LogLevel, message: unknown, context?: string, extra?: Record<string, unknown>): void {
    if (LEVELS[level] > this.threshold) return;
    const entry: Record<string, unknown> = {
      ts: new Date().toISOString(),
      level,
      ctx: context,
    };
    if (typeof message === 'object' && message !== null && !(message instanceof Error)) {
      Object.assign(entry, redact(message) as Record<string, unknown>);
    } else if (message instanceof Error) {
      entry.msg = message.message;
      entry.stack = message.stack?.split('\n').slice(0, 6).join(' | ');
    } else {
      entry.msg = String(message);
    }
    if (extra) Object.assign(entry, redact(extra) as Record<string, unknown>);
    const line = JSON.stringify(entry);
    if (level === 'error' || level === 'warn') process.stderr.write(line + '\n');
    else process.stdout.write(line + '\n');
  }

  // Firma compatible con Nest: (message, ...optionalParams) donde el último suele ser el contexto.
  log(message: unknown, ...optional: unknown[]): void {
    this.write('info', message, this.ctx(optional));
  }
  error(message: unknown, ...optional: unknown[]): void {
    const ctx = this.ctx(optional);
    const trace = optional.length > 1 && typeof optional[0] === 'string' ? optional[0] : undefined;
    this.write('error', message, ctx, trace ? { trace: trace.split('\n').slice(0, 6).join(' | ') } : undefined);
  }
  warn(message: unknown, ...optional: unknown[]): void {
    this.write('warn', message, this.ctx(optional));
  }
  debug(message: unknown, ...optional: unknown[]): void {
    this.write('debug', message, this.ctx(optional));
  }
  verbose(message: unknown, ...optional: unknown[]): void {
    this.write('debug', message, this.ctx(optional));
  }

  /** Log estructurado explícito */
  event(level: LogLevel, context: string, fields: Record<string, unknown>): void {
    this.write(level, fields, context);
  }

  private ctx(optional: unknown[]): string | undefined {
    const last = optional[optional.length - 1];
    return typeof last === 'string' ? last : undefined;
  }
}

/** Instancia compartida (Nest también la usa vía app.useLogger). */
export const logger = new JsonLogger(process.env.LOG_LEVEL ?? 'info');
