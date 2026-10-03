import { Injectable } from '@nestjs/common';
import { execFile } from 'node:child_process';
import { ConfigService } from '../config/config.service';
import { MetricsService } from '../metrics/metrics.service';
import { CloudflareRangesService } from '../cloudflare/cloudflare-ranges.service';
import { ParsedIp, isPublicUnicast, isSafeNftToken } from '../common/ip.util';
import { logger } from '../common/logger';

/**
 * Integración nftables SEGURA (punto 39):
 *
 *  - Nunca se usa una shell: execFile("/usr/sbin/nft", [argv...]).
 *  - El elemento que se inserta es la forma CANÓNICA producida por ipaddr.js (solo [0-9a-f:./]),
 *    re-validada con una lista blanca de caracteres: imposible inyectar sintaxis nft.
 *  - Solo IPs públicas unicast, nunca Cloudflare, nunca allowlist (lo comprueba BanService).
 *  - Solo IPs TCP de conexiones DIRECTAS: si la petición vino por Cloudflare, banear la IP del
 *    visitante en nftables no sirve (su TCP es de Cloudflare) → se banea en Nginx/Cloudflare.
 *  - El servicio NO corre como root: systemd le da solo CAP_NET_ADMIN (drop-in opcional).
 *  - Cola con concurrencia 1 y tamaño máximo: un ataque masivo no genera miles de procesos.
 */
@Injectable()
export class FirewallService {
  private queue: (() => Promise<void>)[] = [];
  private running = false;
  static readonly MAX_QUEUE = 500;

  constructor(
    private readonly config: ConfigService,
    private readonly metrics: MetricsService,
    private readonly cfRanges: CloudflareRangesService,
  ) {}

  get enabled(): boolean {
    return this.config.env.enableNftables;
  }

  /** ¿Se puede banear esta IP TCP en nftables? */
  eligible(tcpIp: ParsedIp | null): boolean {
    return !!tcpIp && this.enabled && isPublicUnicast(tcpIp) && !this.cfRanges.isCloudflare(tcpIp);
  }

  /** token: IPv4 "1.2.3.4" o IPv6 "2001:db8::/64" (clave de reputación) */
  ban(token: string, version: 4 | 6, seconds: number): void {
    if (!this.enabled) return;
    const t = token.toLowerCase();
    if (!isSafeNftToken(t)) {
      logger.error(`Token nft rechazado por validación: ${JSON.stringify(token)}`, 'Firewall');
      return;
    }
    const sec = Math.max(60, Math.min(Math.floor(seconds), 30 * 86400));
    const set = version === 4 ? 'attackers_v4' : 'attackers_v6';
    this.enqueue(async () => {
      // delete + add para refrescar el timeout si ya existía (add no actualiza el timeout)
      await this.nft(['delete', 'element', 'inet', 'smartguard', set, `{ ${t} }`], true);
      await this.nft(['add', 'element', 'inet', 'smartguard', set, `{ ${t} timeout ${sec}s }`]);
    });
  }

  unban(token: string, version: 4 | 6): void {
    if (!this.enabled) return;
    const t = token.toLowerCase();
    if (!isSafeNftToken(t)) return;
    const set = version === 4 ? 'attackers_v4' : 'attackers_v6';
    this.enqueue(() => this.nft(['delete', 'element', 'inet', 'smartguard', set, `{ ${t} }`], true));
  }

  private enqueue(job: () => Promise<void>): void {
    if (this.queue.length >= FirewallService.MAX_QUEUE) {
      this.metrics.firewallOps.inc({ op: 'queue', result: 'dropped' });
      return;
    }
    this.queue.push(job);
    if (!this.running) void this.drain();
  }

  private async drain(): Promise<void> {
    this.running = true;
    while (this.queue.length) {
      const job = this.queue.shift()!;
      try {
        await job();
      } catch {
        /* ya registrado */
      }
    }
    this.running = false;
  }

  private nft(args: string[], ignoreError = false): Promise<void> {
    return new Promise((resolve, reject) => {
      execFile(this.config.env.nftBinary, args, { timeout: 5000, windowsHide: true, env: {} }, (err, _stdout, stderr) => {
        const op = args[0] ?? 'nft';
        if (err) {
          this.metrics.firewallOps.inc({ op, result: 'error' });
          if (!ignoreError) {
            logger.warn(`nft ${args.slice(0, 5).join(' ')} falló: ${String(stderr || err.message).trim().slice(0, 200)}`, 'Firewall');
            reject(err);
            return;
          }
          resolve();
          return;
        }
        this.metrics.firewallOps.inc({ op, result: 'ok' });
        resolve();
      });
    });
  }
}
