import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../account/entity/user.entity';
import { AuthRepository } from './auth.repository';
import { MailModule } from '../mail/mail.module';
import { RoleEntity } from '../role/role.entity';
import { RefreshTokenEntity } from '../token/refresh-token.entity';
import { GoogleAuthService } from './oauth/google.service';
import { OAuthAccountEntity } from './oauth/oauth.entity';
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
