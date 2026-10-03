import { createHash, randomUUID } from 'node:crypto';
import { RequestContext } from '../common/types';
import { ParsedIp, ipKey, parseIp } from '../common/ip.util';
import { MAX_UA_LEN, analyzeUri, cleanText, normalizeHost } from '../common/uri.util';
import { ConfigService } from '../config/config.service';

export interface RawRequest {
  ip: string | undefined;
  tcpIp?: string | undefined;
  method?: string;
  uri?: string;
  host?: string;
  userAgent?: string;
  acceptLanguage?: string;
  requestId?: string;
  country?: string;
}

export interface BuiltContext {
  ctx: RequestContext;
  ip: ParsedIp;
  tcp: ParsedIp | null;
  fpKey: string;
}

const METHOD_RE = /^[A-Z]{3,10}$/;
const REQ_ID_RE = /^[A-Za-z0-9-]{8,64}$/;

/**
 * Normaliza lo que llega de Nginx (cabeceras auth_request) o de una línea de log.
 *
 * Anti-spoofing (punto 69): la IP del cliente SOLO sale de X-Real-IP, que Nginx rellena con
 * $remote_addr YA resuelto por el módulo realip (que solo acepta CF-Connecting-IP si la IP TCP es de
 * Cloudflare). SmartGuard NUNCA lee X-Forwarded-For ni CF-Connecting-IP por su cuenta, y la API solo
 * acepta llamadas desde loopback con el secreto compartido de Nginx.
 *
 * Host (punto 70): se normaliza y, si no pertenece a un sitio configurado, se usa "_unknown";
 * el Host del cliente nunca se usa como clave de Redis.
 */
export function buildContext(raw: RawRequest, config: ConfigService, isCloudflare: (ip: ParsedIp) => boolean): BuiltContext | null {
  const ip = parseIp(raw.ip);
  if (!ip) return null;
  const tcp = parseIp(raw.tcpIp);
  const viaCloudflare = !!tcp && tcp.address !== ip.address && isCloudflare(tcp);

  const method = (raw.method ?? 'GET').toUpperCase();
  const host = normalizeHost(raw.host);
  const site = host ? config.siteForHost(host)?.name ?? '_unknown' : '_unknown';
  const uri = analyzeUri(raw.uri ?? '/');
  const userAgent = cleanText(raw.userAgent, MAX_UA_LEN);
  const acceptLanguage = cleanText(raw.acceptLanguage, 64);
  const key = ipKey(ip, config.env.ipv6Prefix);
  const country = viaCloudflare && raw.country && /^[A-Z]{2}$/.test(raw.country) ? raw.country : undefined;

  const ctx: RequestContext = {
    requestId: raw.requestId && REQ_ID_RE.test(raw.requestId) ? raw.requestId : randomUUID(),
    ip: ip.address,
    ipKey: key,
    ipVersion: ip.version,
    tcpIp: tcp?.address ?? null,
    viaCloudflare,
    method: METHOD_RE.test(method) ? method : 'INVALID',
    host: site === '_unknown' ? '_unknown' : host,
    rawHost: host,
    site,
    rawUri: (raw.uri ?? '/').slice(0, 4096),
    path: uri.path,
    query: uri.query,
    decodedQuery: uri.decodedQuery,
    userAgent,
    acceptLanguage,
    country,
    uriFlags: { malformed: uri.malformed, tooLong: uri.tooLong, dotSegments: uri.dotSegments, nullByte: uri.nullByte },
  };
  return { ctx, ip, tcp, fpKey: fingerprint(key, userAgent) };
}

/**
 * Huella temporal NO invasiva (punto 68): hash de clave IP + User-Agent.
 * Sin cookies, sin canvas, sin tracking. Sirve para castigar señales de baja confianza
 * sin afectar al resto de usuarios detrás del mismo NAT.
 */
export function fingerprint(ipKeyValue: string, userAgent: string): string {
  return createHash('sha1').update(ipKeyValue).update('\n').update(userAgent).digest('hex').slice(0, 20);
}
