import { DataSource, In, Repository } from 'typeorm';
import { UserEntity } from '../entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { OAuthAccountEntity } from '../entities/oauth.entity';
import { RefreshTokenEntity } from '../entities/refresh-token.entity';
import { HobbyEntity } from '../entities/hobby.entity';

export class AccountRepository {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepo: Repository<UserEntity>,
    @InjectRepository(OAuthAccountEntity)
    private readonly oAuthAccountRepo: Repository<OAuthAccountEntity>,
    @InjectRepository(HobbyEntity)
    private readonly hobbyRepo: Repository<HobbyEntity>,
    private readonly daraSource: DataSource,
  ) {}
  async findUserByEmail(email: string) {
    return this.userRepo.findOne({
      where: { email: email },
      relations: {
        roles: true,
        hobbies: true,
        cefrLevel: true,
        oauthAccounts: true,
      },
      select: {
        id: true,
        hashedpassword: true,
        username: true,
        email: true,
        isActive: true,
      },
    });
  }
  async findOAuthAccountByproviderAccountId(providerAccountId: string) {
    return await this.oAuthAccountRepo.findOne({
      where: { providerAccountId: providerAccountId },
      relations: { user: true },
    });
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
  async getAllHobbies() {
    return await this.hobbyRepo.find();
  }
  async saveHobbies(user: UserEntity) {
    return await this.userRepo.save(user);
  }
  async countExistHobbies(hobbies: HobbyEntity[]) {
    return await this.hobbyRepo.count({
      where: { id: In(hobbies.map((hobby) => hobby.id)) },
    });
  }
  async checkExistUserByID(id: string) {
    return await this.userRepo.exists({ where: { id: id } });
  }
  async updateUserNameByID(id: string, username: string) {
    return await this.userRepo.update({ id: id }, { username: username });
  }
}
