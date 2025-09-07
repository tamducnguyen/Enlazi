import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Request } from 'express';
import { UserEntity } from 'src/modules/account/entity/user.entity';
import { AuthUser } from 'src/modules/token/authuser.interface';
import { Repository } from 'typeorm';
import { message } from '../constants.common';
@Injectable()
export class ValidUser implements CanActivate {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepo: Repository<UserEntity>,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const user = request.user as AuthUser;
    //for public routes
    if (!request.user) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const email = request.body.email as string;
      if (!email) {
        throw new BadRequestException(message.user.not_exist);
      }
      const isUserExist = await this.userRepo.exists({
        where: { email: email, isActive: true },
      });
      if (!isUserExist) {
        throw new UnauthorizedException(message.user.not_exist);
      }
      return true;
    }
    //for routes need token
    if (!user.sub) {
      throw new UnauthorizedException(message.user.invalid_payload_token);
    }
    const isUserExist = await this.userRepo.exists({
      where: { id: user.sub, isActive: true },
    });
    if (!isUserExist) {
      throw new UnauthorizedException(message.user.invalid_payload_token);
    }
    return true;
  }
}
