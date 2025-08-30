import {
  Injectable,
  BadRequestException,
  Inject,
  UnauthorizedException,
  HttpStatus,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { SignUpDTO } from './dto/user.singup.dto';
import { AuthRepository } from './auth.repository';
import {
  cookieOptions,
  message,
  prefix_key_cached,
  ttlCacheEmail,
} from '../common/constants.common';
import { MailService } from '../mail/mail.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { generateVerificationCode } from '../common/helper/generatecode.helper';
import { HashHelper } from '../common/helper/hash.helper';
import { SignInDTO } from './dto/user.singin.dto';
import { JwtService } from '@nestjs/jwt';
import { Role } from '../role/roles.enum';
import { VerifyDTO } from './dto/user.verify.dto';
import { ConfigService } from '@nestjs/config';
import { AuthUser } from '../token/authuser.interface';
import { v4 } from 'uuid';
import { RefreshDTO } from './dto/users.refresh.dto';
import { SignOutDTO } from './dto/users.signout.dto';
import { sendResponse } from '../common/helper/response.helper';
import { ForgotPasswordDTO } from './dto/users.forgotpassword.dto';
import { VerifyForgotPasswordDTO } from './dto/users.verifyforgpass.dto';
import { Provider } from './oauth/provider.enum';
import { UserEntity } from '../users/users.entity';
import { ttlCache } from '../common/constants.common';
import { RefreshTokenEntity } from '../token/refresh-token.entity';
@Injectable()
export class AuthService {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly authRepository: AuthRepository,
    private readonly mailService: MailService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  /**
   * Generates, sends, and caches a verification code via email.
   *
   * @param email - The recipient's email
   */
  private async sendAndCacheVerificationCode(email: string) {
    const verifyCode = generateVerificationCode();
    await this.mailService.sendWelcomeAndVerifyCode(email, verifyCode);
    const key = prefix_key_cached.verify_code + email;
    await this.cacheManager.set(key, verifyCode, ttlCache); //TTL = 5 minutes
  }
  /**
   * Registers a new user or updates an existing one in cache memory.
   *
   * - If a user with the given email exists, throws a BadRequestException.
   * - If the user does not exist, creates a new user and sends a verification code.
   *
   * @param userCreatedDTO - The data transfer object containing user input (email, username, password)
   * @returns A success message indicating the verification code has been sent
   * @throws BadRequestException - If the user already exists
   */
  async signUp(signUpDTO: SignUpDTO) {
    const { email } = signUpDTO;
    const oAuthAccountFounded = await this.authRepository.findOAuthAccount(
      Provider.Credential,
      email,
    );
    if (oAuthAccountFounded) {
      throw new BadRequestException(message.user.exist);
    }
    const keySendMail = prefix_key_cached.sendmail + email;
    const isSendmail = await this.cacheManager.get<boolean>(keySendMail);
    if (isSendmail) {
      throw new BadRequestException(message.user.wait_before_resend);
    }
    const userRole = await this.authRepository.findRoleByName(Role.Student);
    if (!userRole) {
      throw new Error(message.user.role_not_exist);
    }
    const userEntity: Partial<UserEntity> = {
      email: signUpDTO.email,
      username: signUpDTO.username,
      hashedpassword: await HashHelper.hash(signUpDTO.password),
      roles: [userRole],
    };
    await this.cacheManager.set(
      prefix_key_cached.signupinfo + email,
      userEntity,
      ttlCache,
    );
    await this.sendAndCacheVerificationCode(email);
    await this.cacheManager.set(
      prefix_key_cached.sendmail + email,
      true,
      ttlCacheEmail,
    );
    return sendResponse(
      HttpStatus.CREATED,
      message.user.send_code_successfully,
    );
  }
  /**
   * Verifies a user's account using the provided verification code.
   * - If user doesn't exist, throws a BadRequestException
   * - Compares the provided code with the one stored in Cache memory.
   * - If valid, create OAuthAccount with/without user account and removes cache keys from Cache memory.
   *
   * @param email - The user's email
   * @param code - The verification code entered by the user
   * @returns A success message upon successful verification
   * @throws BadRequestException - If the code is invalid or expired or user got banned
   */
  async verifyUser(verifyDTO: VerifyDTO) {
    const { email, verify_code } = verifyDTO;
    const keyUserBanned = prefix_key_cached.userbanned + email;
    //if user banned throw BadExceptionResponse
    const isBanned = await this.cacheManager.get<boolean>(keyUserBanned);
    if (isBanned) {
      throw new BadRequestException(message.user.userbanned);
    }
    //if oAuthAccount exist throw BadExceptionResponse
    const oAuthAccountFounded = await this.authRepository.findOAuthAccount(
      Provider.Credential,
      email,
    );
    if (oAuthAccountFounded) {
      throw new BadRequestException(message.user.exist);
    }
    //if dont have sign up infor or verefy code cached in memory with user's email throw BadExceptionResponse
    const keyCacheSignUpInfo = prefix_key_cached.signupinfo + email;
    const keyCacheCode = prefix_key_cached.verify_code + email;
    const codeFromCacheStorage =
      await this.cacheManager.get<string>(keyCacheCode);
    const signUpInfoCached =
      await this.cacheManager.get<Partial<UserEntity>>(keyCacheSignUpInfo);
    if (!signUpInfoCached || !codeFromCacheStorage) {
      throw new BadRequestException(message.user.not_exist);
    }
    //get attempts, if attempts equal or greater than 5, user got banned
    const keyAttempNumber = prefix_key_cached.number_verified + email;
    let attempts = (await this.cacheManager.get<number>(keyAttempNumber)) || 0;
    if (String(verify_code) !== String(codeFromCacheStorage)) {
      await this.cacheManager.set<number>(
        keyAttempNumber,
        ++attempts,
        ttlCache,
      );
      if (attempts >= 5) {
        await this.cacheManager.set<boolean>(keyUserBanned, true, ttlCache);
        await this.cacheManager.del(keyAttempNumber);
        throw new BadRequestException(message.user.userbanned);
      }
      throw new BadRequestException(message.user.wrong_verified_code);
    }
    const oAuthAccountEntity = {
      provider: Provider.Credential,
      providerAccountId: signUpInfoCached.email,
    };
    //if email exist, create another OAuth account(Credential)
    const userFounded = await this.authRepository.findUserByEmail(email);
    if (userFounded) {
      const userAddedPassword: Partial<UserEntity> = {
        hashedpassword: signUpInfoCached.hashedpassword,
      };
      await this.authRepository.updateUserById(
        userFounded.id,
        userAddedPassword,
      );
      await this.authRepository.createOAuthAccount({
        ...oAuthAccountEntity,
        user: userFounded,
      });
      //del cache
      await this.cacheManager.del(prefix_key_cached.signupinfo + email);
      await this.cacheManager.del(keyAttempNumber);
      await this.cacheManager.del(keyCacheCode);
      return sendResponse(HttpStatus.OK, message.user.verify_successfully);
    }
    //if email not exist create user and OAuth account with transaction
    const userEntity: Partial<UserEntity> = {
      email: signUpInfoCached.email,
      username: signUpInfoCached.username,
      hashedpassword: signUpInfoCached.hashedpassword,
      roles: signUpInfoCached.roles,
    };
    await this.authRepository.createUser(userEntity, oAuthAccountEntity);
    //del cache
    await this.cacheManager.del(prefix_key_cached.signupinfo + email);
    await this.cacheManager.del(keyAttempNumber);
    await this.cacheManager.del(keyCacheCode);
    return sendResponse(HttpStatus.OK, message.user.verify_successfully);
  }
  /**
   * Handles user sign-in process:
   *  - Checks if the user exists.
   *  - Validates if the user has been verified.
   *  - Verifies that the provided password matches the stored hashed password.
   *  - Generates an access token and a refresh token.
   *
   * @param signInDTO - Data transfer object containing:
   *    - email: string - The user's email address.
   *    - password: string - The user's password in plain text.
   *
   * @returns An object containing:
   *    - accesstoken: string - Short-lived access token for authenticated requests.
   *    - refreshtoken: string - Long-lived refresh token for renewing access tokens.
   *
   * @throws BadRequestException - If:
   *    - The user account does not exist (`message.user.not_exist`), OR
   *    - The user account has not been verified (`message.user.verify_require`), OR
   *    - The provided password is incorrect (`message.user.wrong_password`).
   */
  async signIn(signInDTO: SignInDTO, response: Response) {
    const { email, password } = signInDTO;
    const oAuthAccountFounded = await this.authRepository.findOAuthAccount(
      Provider.Credential,
      email,
    );
    if (!oAuthAccountFounded) {
      throw new BadRequestException(message.user.invalid_email_password);
    }
    const userFounded = await this.authRepository.findUserById(
      oAuthAccountFounded.user.id,
    );
    if (!userFounded) {
      throw new Error('Conflict database');
    }
    if (!userFounded.isActive) {
      throw new BadRequestException(message.user.verify_require);
    }
    if (!userFounded.hashedpassword) {
      throw new Error('dont have password');
    }
    const isCorrectPassword = await HashHelper.compare(
      password,
      userFounded.hashedpassword,
    );
    if (!isCorrectPassword) {
      throw new BadRequestException(message.user.invalid_email_password);
    }
    const userInfo = {
      sub: oAuthAccountFounded.user.id,
      email: oAuthAccountFounded.user.email,
      roles: oAuthAccountFounded.user.roles.map((role) => role.name),
    };
    const accessToken = await this.jwtService.signAsync(userInfo);
    const refreshToken = await this.jwtService.signAsync(userInfo, {
      expiresIn: this.configService.get<string>('EXPIRE_IN_RF'),
    });
    const { exp } = this.jwtService.decode<{ exp: number }>(refreshToken) as {
      exp: number;
    };
    const expires_at = new Date(exp * 1000);
    const sessionId = v4();
    //userGuard: API key???
    const refreshTokenHashed = await HashHelper.hash(refreshToken);
    const refreshTokenEntity: Partial<RefreshTokenEntity> = {
      tokenHash: refreshTokenHashed,
      user: oAuthAccountFounded.user,
      expiresAt: expires_at,
      sessionId: sessionId,
    };
    await this.authRepository.saveRefreshToken(refreshTokenEntity);
    const data = {
      accesstoken: accessToken,
      refreshtoken: refreshToken,
      sessionid: sessionId,
    };
    response.cookie(cookieOptions.name.accessToken, accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: cookieOptions.maxAge.accessToken, // 1 hour
    });
    response.cookie(cookieOptions.name.refreshToken, refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: cookieOptions.maxAge.refreshToken, // 1 year
    });
    response.cookie(cookieOptions.name.sessionId, sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: cookieOptions.maxAge.sessionId, // 1 year
    });
    return sendResponse(HttpStatus.OK, message.user.sign_in_successfully, data);
  }
  /**
   * Refreshes an access token using a refresh token and session ID
   * from either the request header or cookies.
   *
   * Steps:
   *  - Reads refreshToken and sessionId from request headers or cookies.
   *  - Validates presence and, if both sources are provided, ensures they match.
   *  - Verifies refreshToken signature using the configured secret.
   *  - Transfer to body and vaidate
   *  - Fetch stored refresh token by sessionId, ensure not revoked.
   *  - Compare provided token with stored hash.
   *  - Retrieve user; if valid, sign a new access token.
   *  - Set new access token in an HttpOnly cookie and return success.
   *
   * Security:
   *  - HttpOnly + Secure cookies to prevent XSS and require HTTPS.
   *  - `sameSite: 'strict'` blocks cross-site requests (adjust if needed).
   *  - Rotation/reuse detection not implemented but recommended.
   */
  async refresh(
    response: Response,
    currentUser: AuthUser,
    refreshDTO: RefreshDTO,
  ) {
    const { refreshToken, sessionId } = refreshDTO;
    const refreshTokenStored =
      await this.authRepository.findRefreshTokenBySessionId(sessionId);
    if (!refreshTokenStored || refreshTokenStored.isRevoked) {
      throw new UnauthorizedException(
        message.auth.refresh_token.invalid_or_expired,
      );
    }

    const isMatchRT = await HashHelper.compare(
      refreshToken,
      refreshTokenStored.tokenHash,
    );
    if (!isMatchRT) {
      throw new UnauthorizedException(
        message.auth.refresh_token.invalid_or_expired,
      );
    }
    const userInfoDecoded = currentUser;
    if (!userInfoDecoded) {
      throw new Error('Dont have req.user from RefreshGuard');
    }
    const userFound = await this.authRepository.findUserById(
      userInfoDecoded.sub,
    );
    if (!userFound) {
      throw new UnauthorizedException(message.user.not_exist);
    }
    // sau khi nâng cấp vai trò thì nên thu hồi lại refreshtoken chứa role cũ
    const userInfo = {
      sub: userFound.id,
      email: userFound.email,
      roles: userFound.roles.map((r) => r.name),
    };
    const accessToken = await this.jwtService.signAsync(userInfo);
    response.cookie(cookieOptions.name.accessToken, accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: cookieOptions.maxAge.accessToken, // 1 hour
    });
    return sendResponse(
      HttpStatus.OK,
      message.user.refresh_token_successfully,
      accessToken,
    );
  }
  /**
   * Signs the user out by revoking the refresh token session and clearing cookies.
   *  - Reads refreshToken and sessionId from request headers or cookies.
   *  - Validates presence and, if both sources are provided, ensures they match.
   *  - Verifies refreshToken signature using the configured secret.
   *  - Transfer to body and vaidate
   *  - Checks that the session exists in the database and is not revoked.
   *  - Compares the provided refreshToken with the stored token hash.
   *  - Clears authentication cookies (accessToken, refreshToken, sessionId).
   *  - Revokes the refresh token in the database to invalidate the session.
   *  - Returns a success response.
   *
   * Security: verification ensures the token belongs to an active session,
   * and revocation prevents reuse. Cookies are cleared to remove local auth data.
   */
  async signOut(res: Response, signOutDTO: SignOutDTO) {
    const { refreshToken, sessionId } = signOutDTO;
    const refreshTokenStored =
      await this.authRepository.findRefreshTokenBySessionId(sessionId);
    if (!refreshTokenStored || refreshTokenStored.isRevoked) {
      throw new UnauthorizedException(
        message.auth.refresh_token.invalid_or_expired,
      );
    }

    const isMatchRT = await HashHelper.compare(
      refreshToken,
      refreshTokenStored.tokenHash,
    );
    if (!isMatchRT) {
      throw new UnauthorizedException(
        message.auth.refresh_token.invalid_or_expired,
      );
    }
    res.clearCookie(cookieOptions.name.accessToken);
    res.clearCookie(cookieOptions.name.refreshToken);
    res.clearCookie(cookieOptions.name.sessionId);
    await this.authRepository.revokeRefreshTokenById(refreshTokenStored.id);
    return sendResponse(HttpStatus.OK, message.user.sign_out_successfully);
  }
  /**
   * Starts the forgot password process:
   *  - Check ban status(5m)
   *  - Checks if the email belongs to an existing, verified user.
   *  - Clears any previous reset code from cache.
   *  - Generates a new verification code, stores it in cache (5 min).
   *  - Sends the code to the user's email.
   *  - Returns a success response.
   *
   * Security: short TTL, cache-based storage, recommend rate limiting and
   * using a generic message to avoid email enumeration.
   */

  async forgotPassword(forgotPasswordDTO: ForgotPasswordDTO) {
    const { email } = forgotPasswordDTO;
    const oAuthAccountFounded = await this.authRepository.findOAuthAccount(
      Provider.Credential,
      email,
    );
    if (!oAuthAccountFounded || !oAuthAccountFounded.user.isActive) {
      throw new BadRequestException(message.user.not_exist);
    }
    const keyUserBanned = prefix_key_cached.userbanned + email;
    const isBanned = await this.cacheManager.get<boolean>(keyUserBanned);
    if (isBanned) {
      throw new BadRequestException(message.user.userbanned);
    }
    const keySendMail = prefix_key_cached.sendmail + email;
    const isSendmail = await this.cacheManager.get(keySendMail);
    if (isSendmail) {
      throw new BadRequestException(message.user.wait_before_resend);
    }
    const key = prefix_key_cached.forgot_password_code + email;
    await this.cacheManager.del(key);
    const verifyCode = generateVerificationCode();
    await this.cacheManager.set(key, verifyCode, ttlCache);
    await this.mailService.sendForgotPassword(email, verifyCode);
    await this.cacheManager.set(keySendMail, true, ttlCacheEmail);
    return sendResponse(HttpStatus.OK, message.user.send_code_successfully);
  }
  /**
   * Verifies forgot password code and resets password:
   *  - Checks 5-minute ban status.
   *  - Validates OAuth account exists and is active.
   *  - On wrong code: increments attempt count (TTL 5 min), bans if >=5.
   *  - On correct code: clears cache, updates hashed password, revokes all refresh tokens.
   *  - Returns success response.
   */

  async verifyAndResetPassword(
    res: Response,
    verifyFPDTO: VerifyForgotPasswordDTO,
  ) {
    const { email, verify_code, password } = verifyFPDTO;
    const keyUserBanned = prefix_key_cached.userbanned + email;
    const isBanned = await this.cacheManager.get<boolean>(keyUserBanned);
    if (isBanned) {
      throw new BadRequestException(message.user.userbanned);
    }
    const oAuthAccountFounded = await this.authRepository.findOAuthAccount(
      Provider.Credential,
      email,
    );
    if (!oAuthAccountFounded || !oAuthAccountFounded.user.isActive) {
      throw new BadRequestException(message.user.not_exist);
    }
    const key = prefix_key_cached.forgot_password_code + email;
    const codeFromCacheStorage = await this.cacheManager.get(key);
    const keyAttempNumber = prefix_key_cached.number_verified + email;
    let attemps = (await this.cacheManager.get<number>(keyAttempNumber)) || 0;
    if (!codeFromCacheStorage || verify_code !== codeFromCacheStorage) {
      await this.cacheManager.set(keyAttempNumber, ++attemps, ttlCache);
      if (attemps >= 5) {
        await this.cacheManager.set(keyUserBanned, true, ttlCache);
        await this.cacheManager.del(keyAttempNumber);
        throw new BadRequestException(message.user.userbanned);
      }
      throw new BadRequestException(message.user.wrong_verified_code);
    }
    await this.cacheManager.del(key);
    await this.cacheManager.del(keyAttempNumber);
    const userEntity: UserEntity = {
      ...oAuthAccountFounded.user,
      hashedpassword: await HashHelper.hash(password),
    };
    await this.authRepository.resetPasswordAndRevokeAllRefreshToken(userEntity);
    res.clearCookie(cookieOptions.name.accessToken);
    res.clearCookie(cookieOptions.name.refreshToken);
    res.clearCookie(cookieOptions.name.sessionId);
    return sendResponse(
      HttpStatus.OK,
      message.user.reset_password_successfully,
    );
  }
}
