/** true al alcanzar el umbral y en cada múltiplo (abuso sostenido escala: 30, 60, 90…). */
export function reached(n: number, threshold: number | undefined): boolean {
  return !!threshold && threshold > 0 && n > 0 && n % threshold === 0;
}

/** Contador de ventana fija por clave, acotado en memoria. */
export class WindowCounter {
  private m = new Map<string, { start: number; n: number; set?: Set<string> }>();
  constructor(private readonly maxKeys = 100_000) {}

  /** Devuelve el recuento tras incrementar (o el tamaño del set distinto si se pasa member). */
  hit(key: string, windowMs: number, now: number, member?: string): number {
    let e = this.m.get(key);
    if (!e || now - e.start > windowMs) {
      e = { start: now, n: 0 };
      this.m.delete(key);
      this.m.set(key, e);
      if (this.m.size > this.maxKeys) {
        const oldest = this.m.keys().next().value;
        if (oldest !== undefined) this.m.delete(oldest);
      }
    }
    if (member !== undefined) {
      e.set ??= new Set();
      // 0 = miembro ya visto (no cambia el recuento de distintos)
      if (e.set.has(member) || e.set.size >= 1000) return 0;
      e.set.add(member);
      return e.set.size;
    }
    return ++e.n;
  }
}
