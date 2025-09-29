import { HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { Provider } from '../enum/provider.enum';
import { AuthRepository } from './auth.repository';
import { sendResponse } from 'src/modules/common/helper/response.helper';
import { Role } from '../enum/role.enum';
import { cookieOptions, message } from 'src/modules/common/constants.common';
import { RoleEntity } from '../entities/role.entity';
import { v4 } from 'uuid';
import { ExchangeCodeDTO } from './dto/auth.exchangecode.dto';
import { Response } from 'express';
import { sendCookie } from 'src/modules/common/helper/cookie.helper';

@Injectable()
export class GoogleAuthService {
  private client: OAuth2Client;
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly authRepository: AuthRepository,
  ) {
    this.client = new OAuth2Client(
      this.configService.get('GOOGLE_CLIENT_ID'),
      this.configService.get('GOOGLE_CLIENT_SECRET'),
      this.configService.get('GOOGLE_REDIRECT_URI'),
    );
  }
  async sendTokens(
    response: Response,
    id: string,
    email: string,
    roles: RoleEntity[],
  ) {
    const userInfo = {
      sub: id,
      email: email,
      roles: roles.map((role) => role.name),
    };
    const sessionId = v4();
    const accessToken = await this.jwtService.signAsync(userInfo);
    const refreshToken = await this.jwtService.signAsync(userInfo, {
      expiresIn: await this.configService.get('EXPIRE_IN_RF'),
    });
    const data = {
      accesstoken: accessToken,
      refreshtoken: refreshToken,
      sessionid: sessionId,
    };
    sendCookie(
      response,
      this.configService,
      cookieOptions.name.accessToken,
      accessToken,
      cookieOptions.maxAge.accessToken,
    );
    sendCookie(
      response,
      this.configService,
      cookieOptions.name.refreshToken,
      refreshToken,
      cookieOptions.maxAge.refreshToken,
    );
    sendCookie(
      response,
      this.configService,
      cookieOptions.name.sessionId,
      sessionId,
      cookieOptions.maxAge.sessionId,
    );
    return sendResponse(
      HttpStatus.OK,
      message.user.sign_in_with_google_successfully,
      data,
    );
  }
  async exchangeCodeForTokens(
    response: Response,
    exchangeCode: ExchangeCodeDTO,
  ) {
    const { code } = exchangeCode;
    const { tokens } = await this.client.getToken(code);
    if (!tokens.id_token) {
      throw new UnauthorizedException(
        message.google_auth_error.id_token_missing,
      );
    }
    const ticket = await this.client.verifyIdToken({
      idToken: tokens.id_token,
      audience: this.configService.get('GOOGLE_CLIENT_ID'),
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      throw new UnauthorizedException(message.google_auth_error.invalid_token);
    }
    if (!payload.email_verified) {
      throw new UnauthorizedException(
        message.google_auth_error.email_not_verified,
      );
    }
    //if OAuthAcount exists,check active status, log in send tokens
    const oAuthAccountFounded = await this.authRepository.findOAuthAccount(
      Provider.Google,
      payload.sub,
    );
    if (oAuthAccountFounded && oAuthAccountFounded.user.isActive) {
      return await this.sendTokens(
        response,
        oAuthAccountFounded.user.id,
        oAuthAccountFounded.user.email,
        oAuthAccountFounded.user.roles,
      );
    }
    //if email exist, create another OAuth account, send tokens
    const userFounded = await this.authRepository.findUserByEmail(
      payload.email,
    );
    if (userFounded) {
      const oAuthAccount = {
        provider: Provider.Google,
        providerAccountId: payload.sub,
        user: userFounded,
      };
      await this.authRepository.createOAuthAccount(oAuthAccount);
      return await this.sendTokens(
        response,
        userFounded.id,
        userFounded.email,
        userFounded.roles,
      );
    }
    //if email not exist create user with OAuth account(Google provider)
    const userRoles = await this.authRepository.findRoleByName(Role.Student);
    if (!userRoles) {
      throw new Error(message.user.role_not_exist);
    }
    const userEntity = {
      email: payload.email,
      username: payload.name,
      roles: [userRoles],
    };
    const oAuthAccountEntity = {
      provider: Provider.Google,
      providerAccountId: payload.sub,
    };
    const userCreated = await this.authRepository.createUser(
      userEntity,
      oAuthAccountEntity,
    );
    return await this.sendTokens(
      response,
      userCreated.id,
      userCreated.email,
      userCreated.roles,
    );
  }
}
