import { Injectable } from '@nestjs/common';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { ConfigService } from '../config/config.service';
import { ReputationService } from '../reputation/reputation.service';
import { detectDeployment } from '../common/deployment';

export interface DiskEntry {
  id: string;
  path: string;
  /** bytes en disco; null si no existe o el servicio no tiene permiso para leerlo */
  bytes: number | null;
}

/** El recorrido del disco se guarda este tiempo: /opt/smartguard tiene miles de archivos. */
const DISK_TTL_MS = 15 * 60_000;

/**
 * Lo que ocupa SmartGuard en el servidor, para el panel: disco por carpeta, memoria del proceso
 * y memoria en Redis. Solo lectura; nunca sale de las carpetas propias de SmartGuard.
 */
@Injectable()
export class SystemInfoService {
  private disk: { at: number; entries: DiskEntry[] } | null = null;
  private scanning: Promise<DiskEntry[]> | null = null;
  /** /opt/smartguard en producción (este archivo vive en dist/admin/) */
  private readonly root = path.resolve(__dirname, '..', '..');

  constructor(
    private readonly config: ConfigService,
    private readonly reputation: ReputationService,
  ) {}

  private dirs(): { id: string; path: string }[] {
    return [
      { id: 'app', path: this.root },
      { id: 'prev', path: `${this.root}.prev` },
      { id: 'src', path: `${this.root}-src` },
      { id: 'config', path: this.config.env.configDir },
      { id: 'nginx', path: '/etc/nginx/smartguard' },
      { id: 'data', path: '/var/lib/smartguard' },
      { id: 'logs', path: path.dirname(this.config.env.analyzerLogPath) },
      { id: 'backups', path: '/etc/nginx/backups' },
    ];
  }

  /** Tamaño en disco de una carpeta (como "du"), sin seguir enlaces. null si no se puede leer. */
  async dirSize(dir: string): Promise<number | null> {
    let total = 0;
    const pending = [dir];
    try {
      total += diskBytes(await fs.lstat(dir));
    } catch {
      return null;
    }
    while (pending.length > 0) {
      const cur = pending.pop()!;
      let handle;
      try {
        handle = await fs.opendir(cur);
      } catch {
        // la carpeta raíz sin permiso no se puede medir; una subcarpeta ilegible se omite
        if (cur === dir) return null;
        continue;
      }
      for await (const ent of handle) {
        const abs = path.join(cur, ent.name);
        try {
          total += diskBytes(await fs.lstat(abs));
        } catch {
          continue;
        }
        if (ent.isDirectory()) pending.push(abs);
      }
    }
    return total;
  }

  private async diskUsage(): Promise<{ at: number; entries: DiskEntry[] }> {
    if (this.disk && Date.now() - this.disk.at < DISK_TTL_MS) return this.disk;
    // una sola pasada aunque lleguen varias peticiones a la vez
    this.scanning ??= (async () => {
      const entries: DiskEntry[] = [];
      for (const d of this.dirs()) entries.push({ ...d, bytes: await this.dirSize(d.path) });
      return entries;
    })();
    try {
      this.disk = { at: Date.now(), entries: await this.scanning };
    } finally {
      this.scanning = null;
    }
    return this.disk;
  }

  async info(): Promise<unknown> {
    const [disk, redis, pkg, commit] = await Promise.all([
      this.diskUsage(),
      this.reputation.call((s) => s.storageInfo()).catch(() => null),
      fs.readFile(path.join(this.root, 'package.json'), 'utf8').then((s) => JSON.parse(s) as { version?: string }).catch(() => ({ version: undefined })),
      fs.readFile(path.join(this.root, 'COMMIT'), 'utf8').then((s) => s.trim().slice(0, 40)).catch(() => ''),
    ]);
    const mem = process.memoryUsage();
    return {
      version: pkg.version ?? '',
      deployment: detectDeployment(),
      commit,
      node: process.version,
      uptimeSec: Math.round(process.uptime()),
      memory: { rss: mem.rss, heapUsed: mem.heapUsed },
      disk: disk.entries,
      diskTotal: disk.entries.reduce((a, e) => a + (e.bytes ?? 0), 0),
      diskScannedAt: disk.at,
      redis: redis ? { ...redis, eventsMax: this.config.env.eventsStreamMaxLen, degraded: this.reputation.degraded } : null,
    };
  }
}

function diskBytes(st: { size: number; blocks?: number }): number {
  // bloques de 512 bytes realmente ocupados; en sistemas sin ese dato, el tamaño aparente
  return st.blocks ? st.blocks * 512 : st.size;
}
