import { Module } from '@nestjs/common';
import { JwtAccessStrategy } from './jwt.strategy';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RefreshTokenEntity } from './refresh-token.entity';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Module({
  providers: [JwtAccessStrategy],
  imports: [
    TypeOrmModule.forFeature([RefreshTokenEntity]),
    PassportModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('SECRET'),
        signOptions: { expiresIn: configService.get<string>('EXPIRE_IN') },
      }),
    }),
  ],
  exports: [JwtModule],
})
export class TokenModule {}
