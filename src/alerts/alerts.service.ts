import { Injectable } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { logger } from '../common/logger';
import { SecurityEvent, Severity } from '../common/types';

/**
 * Alertas (punto 72). Interfaz de "sinks" para conectar Telegram/Discord/Slack/email más adelante.
 * Implementados: LogSink (siempre) y WebhookSink genérico (Slack y Discord aceptan el payload).
 * Con límite global por hora y deduplicación por IP.
 */
export interface AlertSink {
  readonly name: string;
  send(alert: Alert): Promise<void>;
}

export interface Alert {
  title: string;
  severity: Severity;
  ip: string;
  message: string;
  event?: SecurityEvent;
}

const SEV_ORDER: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

class LogSink implements AlertSink {
  readonly name = 'log';
  async send(a: Alert): Promise<void> {
    logger.event('warn', 'ALERT', { title: a.title, severity: a.severity, ip: a.ip, message: a.message });
  }
}

class WebhookSink implements AlertSink {
  readonly name = 'webhook';
  constructor(private readonly url: string) {}
  async send(a: Alert): Promise<void> {
    const text = `[SmartGuard] ${a.title} — ${a.ip}\n${a.message}`;
    await fetch(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text, content: text.slice(0, 1900), severity: a.severity, ip: a.ip }),
      signal: AbortSignal.timeout(5000),
    });
  }
}

@Injectable()
export class AlertsService {
  private sinks: AlertSink[] = [new LogSink()];
  private sentThisHour = 0;
  private hour = 0;
  private recent = new Map<string, number>();

  constructor(private readonly config: ConfigService) {
    if (config.env.alertWebhookUrl) {
      if (!/^https:\/\//.test(config.env.alertWebhookUrl)) {
        logger.warn('ALERT_WEBHOOK_URL debe ser https://; webhook desactivado', 'Alerts');
      } else {
        this.sinks.push(new WebhookSink(config.env.alertWebhookUrl));
      }
    }
  }

  addSink(s: AlertSink): void {
    this.sinks.push(s);
  }

  notify(a: Alert): void {
    const min = (SEV_ORDER as Record<string, number>)[this.config.env.alertMinSeverity] ?? 3;
    if (SEV_ORDER[a.severity] < min) return;
    const h = Math.floor(Date.now() / 3_600_000);
    if (h !== this.hour) {
      this.hour = h;
      this.sentThisHour = 0;
      this.recent.clear();
    }
    const dedupKey = `${a.ip}|${a.title}`;
    if (this.recent.has(dedupKey)) return;
    if (this.sentThisHour >= this.config.env.alertMaxPerHour) return;
    this.recent.set(dedupKey, Date.now());
    this.sentThisHour++;
    for (const s of this.sinks) {
      s.send(a).catch((e: Error) => logger.warn(`Alerta no enviada por ${s.name}: ${e.message}`, 'Alerts'));
    }
  }
}
