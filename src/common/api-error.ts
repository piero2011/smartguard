import { HttpException } from '@nestjs/common';

/**
 * Errores de la API con CÓDIGO estable + parámetros, para que el dashboard los traduzca
 * (inglés/español) sin depender del texto. `message` va en inglés.
 *
 * Respuesta: { statusCode, code, message, params }
 */
export type ApiErrorCode =
  | 'VALIDATION'
  | 'INVALID_VALUE'
  | 'INVALID_IP'
  | 'ALREADY_ALLOWLISTED'
  | 'ALREADY_COVERED'
  | 'IP_ALLOWLISTED'
  | 'ALREADY_BANNED'
  | 'CLOUDFLARE_IP'
  | 'NOT_IN_ALLOWLIST'
  | 'STATIC_ENTRY'
  | 'HOST_REQUIRES_DOMAIN'
  | 'RELOAD_REJECTED'
  | 'INVALID_BOT_PATTERN'
  | 'BOT_PATTERN_TOO_GENERIC'
  | 'BOT_ALREADY_BLOCKED'
  | 'BOT_NOT_BLOCKED';

export class ApiError extends HttpException {
  constructor(status: number, code: ApiErrorCode, message: string, params: Record<string, unknown> = {}) {
    super({ statusCode: status, code, message, params }, status);
  }
}
