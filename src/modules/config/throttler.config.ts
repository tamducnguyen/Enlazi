import { ConfigService } from '@nestjs/config';
import { ThrottlerModuleOptions } from '@nestjs/throttler';

export const throttlerConfig = (
  configService: ConfigService,
): ThrottlerModuleOptions => [
  {
    name: 'low',
    ttl: 60_000,
    limit: configService.getOrThrow<number>('LIMIT_LOW'),
  },
  {
    name: 'medium',
    ttl: 60_000,
    limit: configService.getOrThrow<number>('LIMIT_MEDIUM'),
  },
  {
    name: 'high',
    ttl: 60_000,
    limit: configService.getOrThrow<number>('LIMIT_HIGHT'),
  },
];
