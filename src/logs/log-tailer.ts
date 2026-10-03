import { promises as fs } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { logger } from '../common/logger';

interface TailState {
  ino: number;
  offset: number;
}

/**
 * "tail -F" asíncrono y sin dependencias:
 *  - Solo fs.promises (nunca I/O síncrono en el event loop, punto 78).
 *  - Detecta rotación (cambio de inode o archivo truncado): termina de leer el archivo viejo y
 *    continúa con el nuevo desde el principio.
 *  - Persiste inode+offset para no re-procesar ni perder líneas al reiniciar.
 *  - Lee como máximo MAX_CHUNK por tick y descarta líneas gigantes (> MAX_LINE).
 */
export class LogTailer {
  static readonly MAX_CHUNK = 1024 * 1024;
  static readonly MAX_LINE = 16 * 1024;
  private fh: FileHandle | null = null;
  private ino = 0;
  private offset = 0;
  private partial = '';
  private timer: NodeJS.Timeout | null = null;
  private busy = false;
  private lastStateSave = 0;
  private missingLogged = false;

  constructor(
    private readonly path: string,
    private readonly stateFile: string,
    private readonly onLines: (lines: string[]) => void,
    private readonly intervalMs = 1000,
  ) {}

  async start(): Promise<void> {
    const saved = await this.loadState();
    await this.open(saved);
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.saveState(true);
    await this.fh?.close().catch(() => undefined);
    this.fh = null;
  }

  private async open(saved: TailState | null): Promise<void> {
    try {
      const fh = await fs.open(this.path, 'r');
      const st = await fh.stat();
      this.fh = fh;
      this.ino = st.ino;
      // Reanudar si es el mismo archivo; si no, empezar por el final (no re-analizar histórico)
      this.offset = saved && saved.ino === st.ino && saved.offset <= st.size ? saved.offset : st.size;
      this.partial = '';
      this.missingLogged = false;
      logger.log(`Analizando ${this.path} desde offset ${this.offset}`, 'LogTailer');
    } catch (e) {
      this.fh = null;
      if (!this.missingLogged) {
        this.missingLogged = true;
        logger.warn(`No se puede abrir ${this.path}: ${(e as Error).message} (se reintentará)`, 'LogTailer');
      }
    }
  }

  private async tick(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    try {
      if (!this.fh) {
        await this.open(null);
        if (!this.fh) return;
      }
      await this.readAvailable();
      // ¿rotado?
      let st;
      try {
        st = await fs.stat(this.path);
      } catch {
        return; // aún no existe el nuevo archivo tras rotar
      }
      if (st.ino !== this.ino) {
        await this.readAvailable(); // vaciar lo que quede en el archivo viejo
        await this.fh?.close().catch(() => undefined);
        this.fh = null;
        await this.open({ ino: st.ino, offset: 0 });
      } else if (st.size < this.offset) {
        // truncado (copytruncate)
        this.offset = 0;
        this.partial = '';
      }
      await this.saveState(false);
    } catch (e) {
      logger.warn(`LogTailer: ${(e as Error).message}`, 'LogTailer');
    } finally {
      this.busy = false;
    }
  }

  private async readAvailable(): Promise<void> {
    if (!this.fh) return;
    const buf = Buffer.allocUnsafe(64 * 1024);
    let total = 0;
    while (total < LogTailer.MAX_CHUNK) {
      const { bytesRead } = await this.fh.read(buf, 0, buf.length, this.offset);
      if (bytesRead === 0) break;
      this.offset += bytesRead;
      total += bytesRead;
      const text = this.partial + buf.toString('utf8', 0, bytesRead);
      const parts = text.split('\n');
      this.partial = parts.pop() ?? '';
      if (this.partial.length > LogTailer.MAX_LINE) this.partial = '';
      const lines = parts.filter((l) => l.length > 0 && l.length <= LogTailer.MAX_LINE);
      if (lines.length) this.onLines(lines);
    }
  }

  private async loadState(): Promise<TailState | null> {
    try {
      const s = JSON.parse(await fs.readFile(this.stateFile, 'utf8')) as TailState;
      return Number.isFinite(s.ino) && Number.isFinite(s.offset) ? s : null;
    } catch {
      return null;
    }
  }

  private async saveState(force: boolean): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastStateSave < 10_000) return;
    this.lastStateSave = now;
    try {
      const tmp = `${this.stateFile}.tmp`;
      await fs.writeFile(tmp, JSON.stringify({ ino: this.ino, offset: this.offset }));
      await fs.rename(tmp, this.stateFile);
    } catch {
      /* directorio de estado no escribible: se continúa sin persistir */
    }
  }
}
