import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '../enum/role.enum';
import { ROLES_KEY } from './role.decorator';
import { Request } from 'express';
import { AuthUser } from '../token/authuser.interface';
import { message } from 'src/modules/common/constants.common';
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) {
      return true;
    }
    const request = context.switchToHttp().getRequest<Request>();
    const user = request.user as AuthUser;
    const hasRole = () =>
      user.roles.some((role: Role) => requiredRoles.includes(role));

    if (!user || !user.roles || !hasRole()) {
      throw new ForbiddenException(message.user.forbidden);
    }
    return true;
  }
}
