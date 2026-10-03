import { Component, Injectable, computed, effect, inject, input, signal } from '@angular/core';
import { Api, IpInfo } from './api.service';
import { TPipe } from './i18n';

/** Quita el sufijo de prefijo de una clave de IP ("2001:db8::/64" → "2001:db8::"). */
function address(ip: string): string {
  return ip.split('/')[0] ?? ip;
}

/**
 * Caché compartida de "a quién pertenece cada IP". Cada <sg-ip> pide la suya; las peticiones se
 * agrupan (hasta 50 IPs por llamada). Es información auxiliar: si falla, simplemente no se muestra.
 */
@Injectable({ providedIn: 'root' })
export class IpInfoStore {
  private readonly api = inject(Api);
  readonly map = signal<Record<string, IpInfo | null>>({});
  private readonly asked = new Set<string>();
  private queue: string[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;

  want(ip: string): void {
    const a = address(ip);
    if (!a || this.asked.has(a)) return;
    this.asked.add(a);
    this.queue.push(a);
    this.timer ??= setTimeout(() => void this.flush(), 40);
  }

  get(ip: string): IpInfo | null {
    return this.map()[address(ip)] ?? null;
  }

  private async flush(): Promise<void> {
    this.timer = null;
    const all = this.queue;
    this.queue = [];
    for (let i = 0; i < all.length; i += 50) {
      const batch = all.slice(i, i + 50);
      try {
        const { items } = await this.api.ipInfo(batch);
        this.map.update((m) => ({ ...m, ...items }));
      } catch {
        for (const ip of batch) this.asked.delete(ip); // se reintenta en el próximo refresco
      }
    }
  }
}

/** Una IP con su país y el dueño de la red debajo (p. ej. "US · DigitalOcean, LLC  centro de datos"). */
@Component({
  selector: 'sg-ip',
  imports: [TPipe],
  template: `
    <code>{{ ip() }}</code>
    @if (info(); as i) {
      <span class="ipinfo" [title]="tooltip(i)">
        {{ i.country }}{{ i.country && i.org ? ' · ' : '' }}{{ i.org }}
        @if (i.cloudflare) { <span class="tag cf">Cloudflare</span> }
        @else if (i.hosting) { <span class="tag">{{ 'ip.hosting' | t }}</span> }
      </span>
    }
  `,
})
export class IpComponent {
  private readonly store = inject(IpInfoStore);
  readonly ip = input.required<string>();
  readonly info = computed(() => this.store.get(this.ip()));

  constructor() {
    effect(() => this.store.want(this.ip()));
  }

  tooltip(i: IpInfo): string {
    return [i.asn ? `AS${i.asn}` : '', i.prefix].filter(Boolean).join(' · ');
  }
}
