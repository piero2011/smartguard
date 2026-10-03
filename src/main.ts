import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { AppModule } from './app.module';
import { ConfigService } from './config/config.service';
import { RedisService } from './redis/redis.service';
import { MetricsService } from './metrics/metrics.service';
import { logger } from './common/logger';

export function createAdapter(): FastifyAdapter {
  return new FastifyAdapter({
    logger: false,
    trustProxy: false, // nunca confiar en X-Forwarded-For
    bodyLimit: 16 * 1024, // la API solo recibe JSON pequeños
    connectionTimeout: 10_000,
    // mayor que keepalive_timeout del upstream en Nginx para evitar carreras de cierre
    keepAliveTimeout: 75_000,
    requestTimeout: 10_000,
    routerOptions: { maxParamLength: 128 },
  });
}

/**
 * Sin ValidationPipe ni DTOs: cada endpoint valida con decoradores de parámetro
 * (@ValidBody, @ValidQuery, @IpParam — ver src/common/validation.ts).
 */
export function configureApp(app: NestFastifyApplication): void {
  app.enableShutdownHooks();
}

async function bootstrap(): Promise<void> {
  process.on('unhandledRejection', (e) => logger.error(`unhandledRejection: ${(e as Error)?.message ?? e}`, 'Process'));

  const app = await NestFactory.create<NestFastifyApplication>(AppModule.forRoot(), createAdapter(), {
    logger,
    bufferLogs: false,
  });
  configureApp(app);

  const config = app.get(ConfigService);
  logger.setLevel(config.env.logLevel);
  const metrics = app.get(MetricsService);
  app.get(RedisService).onError = () => metrics.redisErrors.inc();

  const { port, bindAddress } = config.env;
  await app.listen(port, bindAddress);
  logger.event('info', 'Bootstrap', {
    msg: 'SmartGuard iniciado',
    listen: `${bindAddress}:${port}`,
    mode: config.env.auditMode ? 'AUDIT' : 'ENFORCE',
    redis: config.env.redisEnabled,
    nftables: config.env.enableNftables,
    cloudflare: config.env.enableCloudflare,
    analyzer: config.env.analyzerEnabled,
  });
}

if (require.main === module) {
  bootstrap().catch((e: Error) => {
    logger.error(`Arranque fallido: ${e.message}`, 'Bootstrap');
    process.exit(1);
  });
}
