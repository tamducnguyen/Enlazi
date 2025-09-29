import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { UserEntity } from '../entities/user.entity';
import { Role } from '../enum/role.enum';
import { RoleEntity } from '../entities/role.entity';
import { RefreshTokenEntity } from '../entities/refresh-token.entity';
import { OAuthAccountEntity } from '../entities/oauth.entity';
import { Provider } from '../enum/provider.enum';
@Injectable()
export class AuthRepository {
  constructor(
    @InjectRepository(UserEntity)
    private userRepo: Repository<UserEntity>,
    @InjectRepository(RoleEntity)
    private roleRepo: Repository<RoleEntity>,
    @InjectRepository(RefreshTokenEntity)
    private refreshTokenRepo: Repository<RefreshTokenEntity>,
    @InjectRepository(OAuthAccountEntity)
    private oAuthAccountRepo: Repository<OAuthAccountEntity>,
    private readonly daraSource: DataSource,
  ) {}
  async checkUserExist(email: string) {
    return await this.userRepo.exists({ where: { email: email } });
  }
  async createUser(
    user: Partial<UserEntity>,
    oAuthAccount: Partial<OAuthAccountEntity>,
  ): Promise<UserEntity> {
    return await this.daraSource.transaction<UserEntity>(async (manager) => {
      const userRepoTransaction = manager.getRepository(UserEntity);
      const oAuthAccountRepoTransaction =
        manager.getRepository(OAuthAccountEntity);
      const userCreate = await userRepoTransaction.save(user);
      await oAuthAccountRepoTransaction.save({
        ...oAuthAccount,
        user: userCreate,
      });
      return userCreate;
    });
  }

  async switchIsVerifiedIntoFalse(email: string) {
    await this.userRepo.update({ email: email }, { isActive: false });
  }

  async findUserByEmail(email: string) {
    return await this.userRepo.findOne({
      select: {
        id: true,
        email: true,
        isActive: true,
        hashedpassword: true,
      },
      relations: { roles: true },
      where: { email: email },
    });
  }
  async findUserById(id: string) {
    return await this.userRepo.findOne({
      select: {
        id: true,
        email: true,
        isActive: true,
        hashedpassword: true,
      },
      relations: { roles: true },
      where: { id: id },
    });
  }
  async updateUserById(id: string, user: Partial<UserEntity>) {
    await this.userRepo.update(id, user);
  }
  async findRoleByName(role: Role) {
    return await this.roleRepo.findOne({ where: { name: role } });
  }
  async saveRefreshToken(refreshToken: Partial<RefreshTokenEntity>) {
    return await this.refreshTokenRepo.save(refreshToken);
  }
  async findRefreshTokenBySessionId(sessionId: string) {
    return await this.refreshTokenRepo.findOne({
      where: { sessionId: sessionId },
    });
  }
  async revokeRefreshTokenById(id: string) {
    await this.refreshTokenRepo.update({ id: id }, { isRevoked: true });
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
  async createOAuthAccount(oAuthAccount: Partial<OAuthAccountEntity>) {
    await this.oAuthAccountRepo.save(oAuthAccount);
  }
  async findOAuthAccount(provider: Provider, providerAccountId: string) {
    return await this.oAuthAccountRepo.findOne({
      where: { provider: provider, providerAccountId: providerAccountId },
      relations: { user: { roles: true } },
    });
  }
}
