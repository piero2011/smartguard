import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { promises as fs } from 'node:fs';
import { ConfigService } from '../config/config.service';
import { CidrSet, ParsedIp } from '../common/ip.util';
import { logger } from '../common/logger';

/**
 * Instantánea de https://www.cloudflare.com/ips-v4 y /ips-v6.
 * Solo se usa si /etc/smartguard/cloudflare-ips.txt (generado por scripts/update-cloudflare-ips.sh)
 * no existe o es inválido. Regenerar con el script; no editar a mano.
 */
export const CLOUDFLARE_SNAPSHOT = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];

/**
 * Rangos de Cloudflare: permiten saber si la IP TCP es un edge de Cloudflare.
 * Uso: jamás banear IPs de Cloudflare en nftables y solo confiar en CF-IPCountry
 * cuando la conexión TCP viene realmente de Cloudflare.
 */
@Injectable()
export class CloudflareRangesService implements OnModuleInit, OnModuleDestroy {
  private set = new CidrSet(CLOUDFLARE_SNAPSHOT);
  private timer: NodeJS.Timeout | null = null;
  source = 'snapshot';

  constructor(private readonly config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    await this.reload();
    // update-cloudflare-ips.sh (timer semanal) reescribe el archivo; se relee cada hora.
    this.timer = setInterval(() => void this.reload(), 3_600_000);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async reload(): Promise<void> {
    try {
      const text = await fs.readFile(this.config.env.cloudflareIpsFile, 'utf8');
      const lines = text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
      const invalid: string[] = [];
      const set = new CidrSet(lines, (v) => invalid.push(v));
      if (invalid.length > 0 || set.size < 10) {
        logger.warn(`cloudflare-ips.txt inválido (${invalid.length} entradas malas, ${set.size} válidas): se mantiene la lista anterior`, 'Cloudflare');
        return;
      }
      this.set = set;
      this.source = this.config.env.cloudflareIpsFile;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') logger.warn(`No se pudo leer cloudflare-ips.txt: ${(e as Error).message}`, 'Cloudflare');
    }
  }

  isCloudflare(ip: ParsedIp | null): boolean {
    return this.set.contains(ip);
  }

  get count(): number {
    return this.set.size;
  }
}
