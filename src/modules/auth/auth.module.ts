import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../users/users.entity';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthRepository } from './auth.repository';
import { JwtStrategy } from './jwt.strategy';
import { UsersService } from '../users/users.service';
import { ConfigService } from '@nestjs/config';
import { MailModule } from '../mail/mail.module';
import { RoleEntity } from './role/roles.entity';
import { RefreshTokenEntity } from './token/refresh-token.entity';

@Module({
  controllers: [AuthController],
  providers: [AuthService, AuthRepository, JwtStrategy, UsersService],
  imports: [
    MailModule,
    TypeOrmModule.forFeature([UserEntity, RoleEntity, RefreshTokenEntity]),
    PassportModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('SECRET'),
        signOptions: { expiresIn: configService.get<string>('EXPIRE_IN') },
      }),
    }),
  ],
  exports: [],
})
export class AuthModule {}
