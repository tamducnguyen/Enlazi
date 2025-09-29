import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../entities/user.entity';
import { AuthRepository } from './auth.repository';
import { MailModule } from '../mail/mail.module';
import { RoleEntity } from '../entities/role.entity';
import { RefreshTokenEntity } from '../entities/refresh-token.entity';
import { GoogleAuthService } from './google.service';
import { OAuthAccountEntity } from '../entities/oauth.entity';
import { TokenModule } from '../token/token.module';

@Module({
  controllers: [AuthController],
  providers: [AuthService, AuthRepository, GoogleAuthService],
  imports: [
    MailModule,
    TypeOrmModule.forFeature([
      UserEntity,
      RoleEntity,
      OAuthAccountEntity,
      RefreshTokenEntity,
    ]),
    TokenModule,
  ],
  exports: [],
})
export class AuthModule {}
