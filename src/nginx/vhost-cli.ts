/**
 * Uso (lo invoca el CLI "smartguard protect|unprotect", como root):
 *   node dist/nginx/vhost-cli.js protect|unprotect [--dry-run] <vhost.conf>...
 * Sin --dry-run escribe los archivos; el CLI se encarga del backup, de "nginx -t" y de revertir.
 * Sale con código 2 si no hay nada que cambiar en ningún archivo.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { protectVhost, unprotectVhost } from './vhost-edit';

const [action, ...rest] = process.argv.slice(2);
const dryRun = rest.includes('--dry-run');
const files = rest.filter((a) => !a.startsWith('--'));
if ((action !== 'protect' && action !== 'unprotect') || files.length === 0) {
  console.error('Uso: vhost-cli protect|unprotect [--dry-run] <vhost.conf>...');
  process.exit(64);
}

let changed = 0;
for (const file of files) {
  const before = readFileSync(file, 'utf8');
  const r = action === 'protect' ? protectVhost(before) : unprotectVhost(before);
  console.log(`\n${file}`);
  for (const c of r.changes) console.log(`  línea ${String(c.line).padStart(4)}  ${c.text}`);
  for (const w of r.warnings) console.log(`  aviso: ${w}`);
  if (r.changes.length === 0) {
    console.log('  sin cambios');
    continue;
  }
  if (action === 'protect') console.log(`  resultado: ${r.decision ? 'Protegido (reglas de Nginx + decisión de SmartGuard)' : 'Parcial (solo reglas y límites de Nginx)'}`);
  changed++;
  if (!dryRun) writeFileSync(file, r.text);
}
process.exit(changed > 0 ? 0 : 2);
