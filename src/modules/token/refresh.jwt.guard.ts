import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthUser } from './authuser.interface';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { message } from 'src/modules/common/constants.common';
@Injectable()
export class RefreshTokenGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const headerRT = request.headers['x-refresh-token'] as string;
    const headerSid = request.headers['x-session-id'] as string;

    const cookieRT = request.cookies['refreshToken'] as string;
    const cookieSid = request.cookies['sessionId'] as string;
    const refreshToken: string = headerRT ?? cookieRT;
    const sessionId: string = headerSid ?? cookieSid;
    if (!refreshToken || !sessionId) {
      throw new BadRequestException(message.auth.refresh_token.missing);
    }

    if (
      headerRT &&
      cookieRT &&
      (headerRT !== cookieRT || cookieSid !== headerSid)
    ) {
      throw new BadRequestException(
        message.auth.refresh_token.not_match_cookie_between_body,
      );
    }
    try {
      const userInfoDecoded = await this.jwtService.verifyAsync<AuthUser>(
        refreshToken,
        {
          secret: this.configService.get<string>('SECRET'),
        },
      );
      const refreshDTO = { refreshToken: refreshToken, sessionId: sessionId };
      request.body = refreshDTO;
      request.user = userInfoDecoded;
      return true;
    } catch {
      throw new UnauthorizedException(
        message.auth.refresh_token.invalid_or_expired,
      );
    }
  }
}
