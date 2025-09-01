import { Module } from '@nestjs/common';
import { AccountController } from './account.controller';
import { AccountService } from './account.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from './entity/user.entity';
import { RolesGuard } from '../role/role.guard';
import { UserRepository } from './account.repository';
import { OAuthAccountEntity } from '../auth/oauth/oauth.entity';
import { RefreshTokenEntity } from '../token/refresh-token.entity';
@Module({
  imports: [
    TypeOrmModule.forFeature([
      UserEntity,
      OAuthAccountEntity,
      RefreshTokenEntity,
    ]),
  ],
  controllers: [AccountController],
  providers: [AccountService, RolesGuard, UserRepository],
})
export class AccountModule {}
