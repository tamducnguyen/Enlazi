import { DataSource, Repository } from 'typeorm';
import { UserEntity } from './entity/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { OAuthAccountEntity } from '../auth/oauth/oauth.entity';
import { RefreshTokenEntity } from '../token/refresh-token.entity';

export class UserRepository {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepo: Repository<UserEntity>,
    @InjectRepository(OAuthAccountEntity)
    private readonly oAuthAccountRepo: Repository<OAuthAccountEntity>,
    @InjectRepository(RefreshTokenEntity)
    private readonly refreshTokenRepo: Repository<RefreshTokenEntity>,
    private readonly daraSource: DataSource,
  ) {}
  async findUserByEmail(email: string) {
    return this.userRepo.findOne({
      where: { email: email },
      select: {
        id: true,
        hashedpassword: true,
        username: true,
        email: true,
        roles: true,
      },
    });
  }
  async findOAuthAccountByproviderAccountId(providerAccountId: string) {
    return await this.oAuthAccountRepo.findOne({
      where: { providerAccountId: providerAccountId },
    });
  }
  async updateUser(userEntity: UserEntity) {
    return await this.userRepo.save(userEntity);
  }
  async resetPasswordAndRevokeAllRefreshToken(user: UserEntity) {
    return await this.daraSource.transaction(async (manager) => {
      const userRepoTransaction = manager.getRepository(UserEntity);
      const refreshTokenRepoTransaction =
        manager.getRepository(RefreshTokenEntity);
      const userUpdated = await userRepoTransaction.save(user);
      await refreshTokenRepoTransaction.update(
        { user: { id: userUpdated.id } },
        { isRevoked: true },
      );
    });
  }
  async getOAuthAccountProviderByUser(user: UserEntity) {
    return await this.oAuthAccountRepo.find({
      where: { user: user },
      select: { provider: true },
    });
  }
}
