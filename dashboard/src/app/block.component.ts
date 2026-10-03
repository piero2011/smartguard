import { Component, inject, input } from '@angular/core';
import { TPipe } from './i18n';
import { IpInfoStore } from './ipinfo';
import { BlockActions } from './ui';

/**
 * Botones de bloqueo de una fila (IP, bot, red). Lo que ya está bloqueado se muestra como etiqueta
 * ("IP bloqueada", "Bot bloqueado", "Red bloqueada") en lugar de volver a ofrecer el botón.
 * El botón de bot solo aparece si se conoce el User-Agent; el de red, si se conoce su red.
 */
@Component({
  selector: 'sg-block',
  imports: [TPipe],
  template: `
    @if (actions.ipBlocked(ipKey(), ip())) {
      <span class="tag done">{{ 'st.ipBlocked' | t }}</span>
    } @else {
      <button class="small danger" (click)="actions.blockIp(ip())">{{ 'ev.blockIp' | t }}</button>
    }
    @if (userAgent()) {
      @if (actions.botBlocked(userAgent()); as p) {
        <span class="tag done" [title]="p">{{ 'st.botBlocked' | t }}</span>
      } @else {
        <button class="small danger" [title]="userAgent()" (click)="actions.blockBot(userAgent())">{{ 'ev.blockBot' | t }}</button>
      }
    }
    @if (ipinfo.network(ip()); as n) {
      @if (actions.netBlocked(n.asn)) {
        <span class="tag done" [title]="n.org">{{ 'st.netBlocked' | t }}</span>
      } @else {
        <button class="small danger" [title]="n.org" (click)="actions.blockNetwork(ip(), n.org)">{{ 'net.block' | t }}</button>
      }
    }
  `,
})
export class BlockButtonsComponent {
  readonly actions = inject(BlockActions);
  readonly ipinfo = inject(IpInfoStore);
  readonly ip = input.required<string>();
  /** Clave de reputación de la IP (en IPv6 es su /64), que es por la que se guardan los bloqueos */
  readonly ipKey = input('');
  readonly userAgent = input('');
}
