import { Module } from '@nestjs/common';
import { AccountController } from './account.controller';
import { AccountService } from './account.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from './entity/user.entity';
import { RolesGuard } from '../role/role.guard';
import { AccountRepository } from './account.repository';
import { OAuthAccountEntity } from '../auth/oauth/oauth.entity';
import { RefreshTokenEntity } from '../token/refresh-token.entity';
import { HobbyEntity } from './entity/hobby.entity';
import { CefrLevelEntity } from './entity/cefrlevel.entity';
@Module({
  imports: [
    TypeOrmModule.forFeature([
      UserEntity,
      OAuthAccountEntity,
      RefreshTokenEntity,
      HobbyEntity,
      CefrLevelEntity,
    ]),
  ],
  controllers: [AccountController],
  providers: [AccountService, RolesGuard, AccountRepository],
})
export class AccountModule {}
