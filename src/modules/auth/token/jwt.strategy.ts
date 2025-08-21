import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Payload } from '../model/payload.model';
import { Request } from 'express';
function cookieExtractor(req: Request): string {
  return req?.cookies?.accessToken as string;
}
@Injectable()
export class JwtAccessStrategy extends PassportStrategy(Strategy) {
  constructor(private configureService: ConfigService) {
    const secret = configureService.get<string>('SECRET');
    if (!secret) {
      throw new Error('Secret not found');
    }
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(), // ƯU TIÊN
        cookieExtractor,
      ]),
      secretOrKey: secret,
    });
  }

  validate(payload: Payload) {
    return payload;
  }
}
