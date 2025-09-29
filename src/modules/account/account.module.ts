import { Module } from '@nestjs/common';
import { AccountController } from './account.controller';
import { AccountService } from './account.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../entities/user.entity';
import { RolesGuard } from '../role/role.guard';
import { AccountRepository } from './account.repository';
import { OAuthAccountEntity } from '../entities/oauth.entity';
import { RefreshTokenEntity } from '../entities/refresh-token.entity';
import { HobbyEntity } from '../entities/hobby.entity';
import { CefrLevelEntity } from '../entities/cefrlevel.entity';
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
