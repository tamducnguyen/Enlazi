import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserEntity } from '../users/users.entity';
import { Role } from './role/roles.enum';
import { RoleEntity } from './role/roles.entity';
import { RefreshTokenEntity } from './token/refresh-token.entity';
@Injectable()
export class AuthRepository {
  constructor(
    @InjectRepository(UserEntity)
    private userRepo: Repository<UserEntity>,
    @InjectRepository(RoleEntity)
    private roleRepo: Repository<RoleEntity>,
    @InjectRepository(RefreshTokenEntity)
    private refreshTokenRepo: Repository<RefreshTokenEntity>,
  ) {}
  async checkUserExist(email: string) {
    return await this.userRepo.exists({ where: { email: email } });
  }
  async createUser(user: Partial<UserEntity>) {
    await this.userRepo.save(user);
  }
  async switchIsVerifiedIntoTrue(email: string) {
    await this.userRepo.update({ email: email }, { isVerified: true });
  }
  async findUserByEmail(email: string) {
    return await this.userRepo.findOne({
      select: {
        id: true,
        email: true,
        isVerified: true,
        roles: { name: true },
        hashedpassword: true,
      },
      where: { email: email },
    });
  }
  async findUserById(id: string) {
    return await this.userRepo.findOne({
      select: {
        id: true,
        email: true,
        isVerified: true,
        roles: { name: true },
        hashedpassword: true,
      },
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
  async resetPasswordByEmail(email: string, hashedpassword: string) {
    await this.userRepo.update(
      { email: email },
      { hashedpassword: hashedpassword },
    );
  }
  async revokeAllRefreshTokenByUser(user: UserEntity) {
    await this.refreshTokenRepo.delete({ user });
  }
}
