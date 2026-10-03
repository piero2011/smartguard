/**
 * Exporta e importa las listas que SmartGuard guarda en Redis (no en archivos): lista blanca
 * dinámica, bloqueos manuales de IP, bots y redes bloqueados, y el modo AUDIT/ENFORCE.
 * Lo usa "smartguard backup / restore", como root, contra la API local:
 *
 *   SG_TOKEN=… SG_API=http://127.0.0.1:3100 node dist/admin/state-cli.js export <archivo.json>
 *   SG_TOKEN=… SG_API=http://127.0.0.1:3100 node dist/admin/state-cli.js import <archivo.json>
 *
 * El token va por variable de entorno para que no aparezca en la lista de procesos.
 */
import { readFileSync, writeFileSync } from 'node:fs';

interface AllowItem {
  value: string;
  type: string;
  target?: string;
  note?: string;
  expiresAt?: number;
}
interface BanItem {
  ip: string;
  scope: string;
  source: string;
  reason: string;
  expiresAt: number;
  audit?: boolean;
}

export interface SavedState {
  version: 1;
  exportedAt: number;
  audit: boolean | null;
  allow: AllowItem[];
  bans: BanItem[];
  bots: { pattern: string; note?: string; expiresAt?: number }[];
  networks: { asn: number; note?: string }[];
}

/**
 * Tiempo que le queda a una entrada, en el formato de la API (dígitos + unidad, máx. 7 dígitos).
 * null = ya caducó. Lo que dura más de ~115 días se expresa en días.
 */
export function remaining(expiresAt: number | undefined, now = Date.now()): string | null | undefined {
  if (expiresAt === undefined) return undefined;
  const sec = Math.floor((expiresAt - now) / 1000);
  if (sec <= 0) return null;
  return sec <= 9_999_999 ? String(sec) : `${Math.ceil(sec / 86_400)}d`;
}

/** Peticiones a la API que reproducen un estado guardado. Lo caducado se omite. */
export function importPlan(state: SavedState, now = Date.now()): { label: string; path: string; body: Record<string, unknown> }[] {
  const plan: { label: string; path: string; body: Record<string, unknown> }[] = [];
  for (const a of state.allow) {
    const ttl = remaining(a.expiresAt, now);
    if (ttl === null) continue;
    // unban: false → restaurar la lista blanca no debe tocar bloqueos
    plan.push({ label: `lista blanca ${a.value}`, path: '/admin/allow', body: { value: a.value, type: a.type, target: a.target ?? 'client', note: a.note || undefined, ttl, unban: false } });
  }
  for (const b of state.bots) {
    const ttl = remaining(b.expiresAt, now);
    if (ttl === null) continue;
    plan.push({ label: `bot ${b.pattern}`, path: '/admin/blocked-bots', body: { pattern: b.pattern, note: b.note || undefined, ttl } });
  }
  for (const n of state.networks) plan.push({ label: `red AS${n.asn}`, path: '/admin/blocked-networks', body: { asn: n.asn, note: n.note || undefined } });
  // Solo los bloqueos manuales de IP: los automáticos los vuelve a decidir SmartGuard por sí mismo
  for (const b of state.bans) {
    if (b.source !== 'MANUAL' || b.scope !== 'ip' || b.audit) continue;
    const duration = remaining(b.expiresAt, now);
    if (!duration) continue;
    plan.push({ label: `bloqueo ${b.ip}`, path: '/admin/ban', body: { ip: b.ip, duration, reason: (b.reason || 'restore').slice(0, 200) } });
  }
  return plan;
}

async function api(method: string, path: string, body?: unknown): Promise<{ status: number; json: unknown }> {
  const res = await fetch(`${process.env['SG_API'] ?? 'http://127.0.0.1:3100'}${path}`, {
    method,
    headers: { authorization: `Bearer ${process.env['SG_TOKEN'] ?? ''}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* respuesta sin cuerpo JSON */
  }
  return { status: res.status, json };
}

export async function exportState(file: string): Promise<void> {
  const get = async <T>(path: string): Promise<T> => {
    const r = await api('GET', path);
    if (r.status !== 200) throw new Error(`GET ${path} → ${r.status}`);
    return r.json as T;
  };
  const bans: BanItem[] = [];
  for (let offset = 0; ; offset += 1000) {
    const page = await get<{ items: BanItem[] }>(`/admin/bans?audit=false&offset=${offset}&limit=1000`);
    bans.push(...page.items);
    if (page.items.length < 1000) break;
  }
  const state: SavedState = {
    version: 1,
    exportedAt: Date.now(),
    audit: (await get<{ audit: boolean }>('/admin/mode')).audit,
    allow: (await get<{ dynamic: AllowItem[] }>('/admin/allow')).dynamic ?? [],
    bans,
    bots: (await get<{ items: SavedState['bots'] }>('/admin/blocked-bots')).items ?? [],
    networks: (await get<{ items: SavedState['networks'] }>('/admin/blocked-networks')).items.map((n) => ({ asn: n.asn, note: n.note })),
  };
  writeFileSync(file, JSON.stringify(state, null, 2), { mode: 0o600 });
  const manual = state.bans.filter((b) => b.source === 'MANUAL' && b.scope === 'ip' && !b.audit).length;
  console.log(`  lista blanca: ${state.allow.length} · bloqueos manuales de IP: ${manual} · bots: ${state.bots.length} · redes: ${state.networks.length}`);
}

export async function importState(file: string): Promise<void> {
  const state = JSON.parse(readFileSync(file, 'utf8')) as SavedState;
  if (state.version !== 1) throw new Error('formato de estado desconocido');
  let ok = 0;
  let already = 0;
  let failed = 0;
  for (const step of importPlan(state)) {
    const r = await api('POST', step.path, step.body);
    if (r.status >= 200 && r.status < 300) ok++;
    else if (r.status === 409) already++;
    else {
      failed++;
      const msg = (r.json as { message?: string } | null)?.message ?? '';
      console.log(`  no se pudo restaurar ${step.label}: ${r.status} ${msg}`);
    }
  }
  console.log(`  listas restauradas: ${ok} nuevas · ${already} ya existían · ${failed} con error`);
  if (failed > 0) process.exitCode = 3;
}

if (require.main === module) {
  const [action, file] = process.argv.slice(2);
  const run = action === 'export' ? exportState : action === 'import' ? importState : null;
  if (!run || !file) {
    console.error('Uso: state-cli export|import <archivo.json>');
    process.exit(64);
  }
  run(file).catch((e: Error) => {
    console.error(`  error: ${e.message}`);
    process.exit(1);
  });
}
