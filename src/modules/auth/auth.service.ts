import {
  Injectable,
  BadRequestException,
  Inject,
  UnauthorizedException,
  InternalServerErrorException,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { SignUpDTO } from './dto/user.singup.dto';
import { AuthRepository } from './auth.repository';
import {
  HttpStatusCodes,
  message,
  prefix_key_cached,
} from '../common/constants.common';
import { MailService } from '../mail/mail.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { generateVerificationCode } from '../common/helper/generatecode';
import { HashHelper } from '../common/helper/hash.helper';
import { SignInDTO } from './dto/user.singin.dto';
import { JwtService } from '@nestjs/jwt';
import { Role } from './role/roles.enum';
import { VerifyDTO } from './dto/user.verify.dto';
import { ConfigService } from '@nestjs/config';
import { Payload } from './model/payload.model';
import { v4 } from 'uuid';
import { RefreshDTO } from './dto/users.refresh.dto';
import { SignOutDTO } from './dto/users.signout.dto';
import { sendResponse } from '../common/helper/response.helper';
import { SendVerifyCodeDTO } from './dto/users.sendverifycode.dto';
import { ForgotPasswordDTO } from './dto/users.forgotpassword.dto';
import { VerifyForgotPasswordDTO } from './dto/users.verifyforgpass.dto';
@Injectable()
export class AuthService {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly authRepository: AuthRepository,
    private readonly mailService: MailService,
    private readonly jwtService: JwtService,
    private readonly configureService: ConfigService,
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
    await this.cacheManager.set(key, verifyCode, 5 * 60 * 1000); //TTL = 5 minutes
  }
  /**
   * Registers a new user or updates an existing one if not yet verified.
   *
   * - If a user with the given email exists and is verified, throws a BadRequestException.
   * - If the user exists but is not verified, updates the user's information and resends the verification code.
   * - If the user does not exist, creates a new user and sends a verification code.
   *
   * @param userCreatedDTO - The data transfer object containing user input (email, username, password)
   * @returns A success message indicating the verification code has been sent
   * @throws BadRequestException - If the user already exists and is verified
   */
  async signUp(signUpDTO: SignUpDTO) {
    const { email } = signUpDTO;
    const userFound = await this.authRepository.findUserByEmail(email);
    if (userFound) {
      if (userFound.isVerified) {
        throw new BadRequestException(message.user.exist);
      }
      const userRole = await this.authRepository.findRoleByName(Role.Student);
      if (!userRole) {
        throw new InternalServerErrorException(message.user.role_not_exist);
      }
      const userEntity = {
        email: signUpDTO.email,
        username: signUpDTO.username,
        hashedpassword: await HashHelper.hash(signUpDTO.password),
      };
      await this.authRepository.updateUserById(userFound.id, userEntity);
      await this.cacheManager.del(prefix_key_cached.verify_code + email);
      await this.sendAndCacheVerificationCode(email);
      return sendResponse(
        HttpStatusCodes.Created,
        message.user.send_code_successfully,
      );
    }
    const userRole = await this.authRepository.findRoleByName(Role.Student);
    if (!userRole) {
      throw new InternalServerErrorException(message.user.role_not_exist);
    }
    const userEntity = {
      email: signUpDTO.email,
      username: signUpDTO.username,
      hashedpassword: await HashHelper.hash(signUpDTO.password),
      roles: [userRole],
    };
    await this.authRepository.createUser(userEntity);
    await this.sendAndCacheVerificationCode(email);
    return sendResponse(
      HttpStatusCodes.Created,
      message.user.send_code_successfully,
    );
  }
  /**
   * Verifies a user's account using the provided verification code.
   * - If user doesn't exist, throws a BadRequestException
   * - Compares the provided code with the one stored in Redis.
   * - If valid, marks the user as verified and removes the code from Redis.
   *
   * @param email - The user's email
   * @param code - The verification code entered by the user
   * @returns A success message upon successful verification
   * @throws BadRequestException - If the code is invalid or expired
   */
  // Triển khai việc lockout nếu quá 5 lần xác minh
  async verifyUser(verifyDTO: VerifyDTO) {
    const { email, verify_code } = verifyDTO;
    const keyUserBanned = prefix_key_cached.userbanned + email;
    const isBanned = await this.cacheManager.get<boolean>(keyUserBanned);
    if (isBanned) {
      throw new BadRequestException(message.user.userbanned);
    }
    const userFound = await this.authRepository.findUserByEmail(email);
    if (!userFound) {
      throw new BadRequestException(message.user.not_exist);
    }
    if (userFound.isVerified) {
      throw new BadRequestException(message.user.already_verified);
    }
    const keyCacheCode = prefix_key_cached.verify_code + email;
    const codeFromCacheStorage = await this.cacheManager.get(keyCacheCode);
    const keyAttempNumber = prefix_key_cached.number_verified + email;
    let attemps = (await this.cacheManager.get<number>(keyAttempNumber)) || 0;
    if (!codeFromCacheStorage || verify_code !== codeFromCacheStorage) {
      await this.cacheManager.set<number>(
        keyAttempNumber,
        ++attemps,
        5 * 60 * 1000,
      );
      if (attemps >= 5) {
        await this.cacheManager.set<boolean>(
          keyUserBanned,
          true,
          5 * 60 * 1000,
        );
        await this.cacheManager.del(keyAttempNumber);
        throw new BadRequestException(message.user.userbanned);
      }
      throw new BadRequestException(message.user.wrong_verified_code);
    }
    await this.authRepository.switchIsVerifiedIntoTrue(email);
    await this.cacheManager.del(keyAttempNumber);
    await this.cacheManager.del(keyCacheCode);
    return sendResponse(HttpStatusCodes.OK, message.user.verify_successfully);
  }
  /**
   * Verifies a user's account:
   *  - Checks ban status (5 min) to prevent brute force.
   *  - Validates user exists and is not already verified.
   *  - Compares provided code with cached code.
   *    + On mismatch: increments failed attempts (TTL 5 min), bans if >=5.
   *    + On match: marks user verified, clears code and attempt counter.
   *  - Returns success response.
   */

  async sendVerifyCode(sendVerifyCodeDTO: SendVerifyCodeDTO) {
    const { email } = sendVerifyCodeDTO;
    const userFound = await this.authRepository.findUserByEmail(email);
    if (!userFound) {
      throw new BadRequestException(message.user.not_exist);
    }
    if (userFound.isVerified) {
      throw new BadRequestException(message.user.already_verified);
    }
    const key = prefix_key_cached.verify_code + email;
    await this.cacheManager.del(key);
    await this.sendAndCacheVerificationCode(email);
    return sendResponse(
      HttpStatusCodes.OK,
      message.user.send_code_successfully,
    );
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
    const userFound = await this.authRepository.findUserByEmail(email);
    if (!userFound) {
      throw new BadRequestException(message.user.not_exist);
    }
    if (!userFound.isVerified) {
      throw new BadRequestException(message.user.verify_require);
    }
    const isCorrectPassword = await HashHelper.compare(
      password,
      userFound.hashedpassword,
    );
    if (!isCorrectPassword) {
      throw new BadRequestException(message.user.wrong_password);
    }
    const userInfo = {
      sub: userFound.id,
      email: email,
      roles: userFound.roles.map((role) => role.name),
    };
    const accessToken = await this.jwtService.signAsync(userInfo);
    const refreshToken = await this.jwtService.signAsync(userInfo, {
      expiresIn: '365d',
    });
    const { exp } = this.jwtService.decode<{ exp: number }>(refreshToken) as {
      exp: number;
    };
    const expires_at = new Date(exp * 1000);
    const sessionId = v4();
    //userGuard: API key???
    const refreshTokenHashed = await HashHelper.hash(refreshToken);
    const refreshTokenEntity = {
      tokenHash: refreshTokenHashed,
      user: userFound,
      expiresAt: expires_at,
      sessionId: sessionId,
    };
    await this.authRepository.saveRefreshToken(refreshTokenEntity);
    const data = {
      accesstoken: accessToken,
      refreshtoken: refreshToken,
      sessionid: sessionId,
    };
    response.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000, // 1 hour
    });
    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
    });
    response.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
    });
    return sendResponse(
      HttpStatusCodes.OK,
      message.user.sign_in_successfully,
      data,
    );
  }
  /**
   * Refreshes an access token using a refresh token and session ID
   * from either the request body or cookies.
   *
   * Steps:
   *  1. Read refreshToken & sessionId (prefer body, fallback to cookies).
   *  2. Validate presence; if both sources exist, ensure they match.
   *  3. Verify refreshToken signature and decode payload.
   *  4. Fetch stored refresh token by sessionId, ensure not revoked.
   *  5. Compare provided token with stored hash.
   *  6. Retrieve user; if valid, sign a new access token.
   *  7. Set new access token in an HttpOnly cookie and return success.
   *
   * Security:
   *  - HttpOnly + Secure cookies to prevent XSS and require HTTPS.
   *  - `sameSite: 'strict'` blocks cross-site requests (adjust if needed).
   *  - Rotation/reuse detection not implemented but recommended.
   */
  async refresh(response: Response, request: Request, refreshDTO?: RefreshDTO) {
    const bodyRT = refreshDTO?.refreshToken;
    const bodySid = refreshDTO?.sessionId;

    const cookieRT = request.cookies?.refreshToken as string;
    const cookieSid = request.cookies?.sessionId as string;

    const refreshToken: string = bodyRT ?? cookieRT;
    const sessionId: string = bodySid ?? cookieSid;

    if (!refreshToken || !sessionId) {
      throw new BadRequestException(message.auth.refresh_token.missing);
    }

    if (bodyRT && cookieRT && (bodyRT !== cookieRT || cookieSid !== bodySid)) {
      throw new BadRequestException(
        message.auth.refresh_token.not_match_cookie_between_body,
      );
    }
    let userInfoDecoded: Payload;
    try {
      userInfoDecoded = await this.jwtService.verifyAsync<Payload>(
        refreshToken,
        {
          secret: this.configureService.get<string>('SECRET'),
        },
      );
    } catch {
      throw new UnauthorizedException(
        message.auth.refresh_token.invalid_or_expired,
      );
    }
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
    response.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000, // 1 hour
    });
    return sendResponse(
      HttpStatusCodes.OK,
      message.user.refresh_token_successfully,
      accessToken,
    );
  }
  /**
   * Signs the user out by revoking the refresh token session and clearing cookies.
   *  - Reads refreshToken and sessionId from request body or cookies.
   *  - Validates presence and, if both sources are provided, ensures they match.
   *  - Verifies refreshToken signature using the configured secret.
   *  - Checks that the session exists in the database and is not revoked.
   *  - Compares the provided refreshToken with the stored token hash.
   *  - Clears authentication cookies (accessToken, refreshToken, sessionId).
   *  - Revokes the refresh token in the database to invalidate the session.
   *  - Returns a success response.
   *
   * Security: verification ensures the token belongs to an active session,
   * and revocation prevents reuse. Cookies are cleared to remove local auth data.
   */
  async signOut(res: Response, req: Request, signOutDTO?: SignOutDTO) {
    const bodyRT = signOutDTO?.refreshToken;
    const bodySid = signOutDTO?.sessionId;

    const cookieRT = req.cookies?.refreshToken as string;
    const cookieSid = req.cookies?.sessionId as string;

    const refreshToken: string = bodyRT ?? cookieRT;
    const sessionId: string = bodySid ?? cookieSid;

    if (!refreshToken || !sessionId) {
      throw new BadRequestException(message.auth.refresh_token.missing);
    }

    if (bodyRT && cookieRT && (bodyRT !== cookieRT || cookieSid !== bodySid)) {
      throw new BadRequestException(
        message.auth.refresh_token.not_match_cookie_between_body,
      );
    }

    try {
      await this.jwtService.verifyAsync<Payload>(refreshToken, {
        secret: this.configureService.get<string>('SECRET'),
      });
    } catch {
      throw new UnauthorizedException(
        message.auth.refresh_token.invalid_or_expired,
      );
    }
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
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.clearCookie('sessionId');
    await this.authRepository.revokeRefreshTokenById(refreshTokenStored.id);
    return sendResponse(HttpStatusCodes.OK, message.user.sign_out_successfully);
  }
  /**
   * Starts the forgot password process:
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
    const userFound = await this.authRepository.findUserByEmail(email);
    if (!userFound || !userFound.isVerified) {
      throw new BadRequestException(message.user.not_exist);
    }
    const key = prefix_key_cached.forgot_password_code + email;
    await this.cacheManager.del(key);
    const verifyCode = generateVerificationCode();
    await this.cacheManager.set(key, verifyCode, 5 * 60 * 1000);
    await this.mailService.sendForgotPassword(email, verifyCode);
    return sendResponse(
      HttpStatusCodes.OK,
      message.user.send_code_successfully,
    );
  }
  /**
   * Verifies forgot password code and resets password:
   *  - Checks 5-minute ban status.
   *  - Validates user exists and is verified.
   *  - On wrong code: increments attempt count (TTL 5 min), bans if >=5.
   *  - On correct code: clears cache, updates hashed password, revokes all refresh tokens.
   *  - Returns success response.
   */

  async verifyAndResetPassword(verifyFPDTO: VerifyForgotPasswordDTO) {
    const { email, verify_code, password } = verifyFPDTO;
    const keyUserBanned = prefix_key_cached.userbanned + email;
    const isBanned = await this.cacheManager.get<boolean>(keyUserBanned);
    if (isBanned) {
      throw new BadRequestException(message.user.userbanned);
    }
    const userFound = await this.authRepository.findUserByEmail(email);
    if (!userFound || !userFound.isVerified) {
      throw new BadRequestException(message.user.not_exist);
    }
    const key = prefix_key_cached.forgot_password_code + email;
    const codeFromCacheStorage = await this.cacheManager.get(key);
    const keyAttempNumber = prefix_key_cached.number_verified + email;
    let attemps = (await this.cacheManager.get<number>(keyAttempNumber)) || 0;
    if (!codeFromCacheStorage || verify_code !== codeFromCacheStorage) {
      await this.cacheManager.set(keyAttempNumber, ++attemps, 5 * 60 * 1000);
      if (attemps >= 5) {
        await this.cacheManager.set(keyUserBanned, true, 5 * 60 * 1000);
        await this.cacheManager.del(keyAttempNumber);
        throw new BadRequestException(message.user.userbanned);
      }
      throw new BadRequestException(message.user.wrong_verified_code);
    }
    await this.cacheManager.del(key);
    await this.cacheManager.del(keyAttempNumber);
    const passwordHashed = await HashHelper.hash(password);
    await this.authRepository.resetPasswordByEmail(email, passwordHashed);
    await this.authRepository.revokeAllRefreshTokenByUser(userFound);
    return sendResponse(
      HttpStatusCodes.OK,
      message.user.reset_password_successfully,
    );
  }
}
