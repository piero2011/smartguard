import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { ConfigService } from '../config/config.service';
import { LocalOnlyGuard } from '../common/security';
import { logger } from '../common/logger';

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

interface Asset {
  body: Buffer;
  type: string;
}

/**
 * Dashboard Angular (punto 41), servido por el propio SmartGuard SOLO en loopback.
 * Acceso: ssh -L 3100:127.0.0.1:3100 usuario@vps  →  http://127.0.0.1:3100/dashboard/
 *
 * - Build de Angular en dashboard/dist/browser (DASHBOARD_DIR para cambiarlo); se carga en memoria.
 * - Solo se sirven archivos del build (lista cerrada): imposible path traversal.
 * - CSP estricta: scripts solo del propio origen; estilos del origen + nonce por petición
 *   (Angular aplica el nonce a sus <style> vía ngCspNonce).
 * - Los datos se piden a /admin/* con el ADMIN_TOKEN (guardado solo en sessionStorage).
 */
@Controller()
@UseGuards(LocalOnlyGuard)
export class DashboardController {
  private assets: Map<string, Asset> | null = null;
  private loading: Promise<Map<string, Asset>> | null = null;

  constructor(private readonly config: ConfigService) {}

  static dir(): string {
    return process.env.DASHBOARD_DIR || path.join(__dirname, '..', '..', 'dashboard', 'dist', 'browser');
  }

  private async load(): Promise<Map<string, Asset>> {
    if (this.assets) return this.assets;
    this.loading ??= (async () => {
      const root = DashboardController.dir();
      const map = new Map<string, Asset>();
      const walk = async (dir: string, rel: string): Promise<void> => {
        for (const ent of await fs.readdir(dir, { withFileTypes: true })) {
          const abs = path.join(dir, ent.name);
          const r = rel ? `${rel}/${ent.name}` : ent.name;
          if (ent.isDirectory()) await walk(abs, r);
          else if (ent.isFile()) {
            const type = TYPES[path.extname(ent.name).toLowerCase()];
            if (type) map.set(r, { body: await fs.readFile(abs), type });
          }
        }
      };
      try {
        await walk(root, '');
      } catch {
        logger.warn(`Dashboard no compilado en ${root} (npm run build:dashboard)`, 'Dashboard');
      }
      this.assets = map;
      return map;
    })();
    return this.loading;
  }

  @Get('dashboard')
  redirect(@Res() reply: FastifyReply): void {
    reply.redirect('/dashboard/', 302);
  }

  @Get('dashboard/*')
  async serve(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    if (!this.config.env.enableDashboard) {
      reply.code(404).send();
      return;
    }
    const assets = await this.load();
    const url = (req.url.split('?')[0] ?? '').replace(/^\/dashboard\/?/, '');
    let rel = '';
    try {
      rel = decodeURIComponent(url);
    } catch {
      rel = '';
    }
    const asset = assets.get(rel);
    reply.header('x-content-type-options', 'nosniff').header('referrer-policy', 'no-referrer').header('x-frame-options', 'DENY');

    if (asset && rel !== 'index.html') {
      reply.header('content-type', asset.type).header('cache-control', 'public, max-age=3600').send(asset.body);
      return;
    }
    // Rutas de la SPA (sin extensión) → index.html con nonce
    if (!asset && /\.[a-z0-9]{1,6}$/i.test(rel)) {
      reply.code(404).send();
      return;
    }
    const index = assets.get('index.html');
    if (!index) {
      reply.code(503).header('content-type', 'text/plain; charset=utf-8').send('SmartGuard dashboard not built. Run: npm run build:dashboard');
      return;
    }
    const nonce = randomBytes(16).toString('base64');
    const html = index.body.toString('utf8').replace(/__CSP_NONCE__/g, nonce);
    reply
      .header('content-type', 'text/html; charset=utf-8')
      .header('cache-control', 'no-store')
      .header(
        'content-security-policy',
        `default-src 'none'; script-src 'self'; style-src 'self' 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'`,
      )
      .send(html);
  }
}
