import { existsSync } from 'node:fs';

/** Cómo está desplegado SmartGuard: en contenedores o instalado en el sistema (systemd). */
export type Deployment = 'docker' | 'system';

/**
 * Detecta el tipo de despliegue. La imagen de Docker lo declara con SMARTGUARD_DEPLOYMENT=docker;
 * si la variable no está, se mira /.dockerenv, que Docker crea dentro de todo contenedor.
 * El panel lo usa para no ofrecer comandos del servidor (smartguard protect, backup…) donde no existen.
 */
export function detectDeployment(env: NodeJS.ProcessEnv = process.env, exists: (p: string) => boolean = existsSync): Deployment {
  if (env['SMARTGUARD_DEPLOYMENT'] === 'docker') return 'docker';
  if (env['SMARTGUARD_DEPLOYMENT'] === 'system') return 'system';
  return exists('/.dockerenv') ? 'docker' : 'system';
}
