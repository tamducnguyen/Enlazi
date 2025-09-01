import {
  BadRequestException,
  ForbiddenException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserEntity } from './entity/user.entity';
import { ChangePasswordDTO } from './dto/changepassword.dto';
import { Response } from 'express';
import { UserRepository } from './account.repository';
import { HashHelper } from '../common/helper/hash.helper';
import { AuthUser } from '../token/authuser.interface';
import { sendResponse } from '../common/helper/response.helper';
import { cookieOptions, message } from '../common/constants.common';

@Injectable()
export class AccountService {
  constructor(private readonly userRepo: UserRepository) {}
  /**
   * Change password process:
   *  + Check whether user's account is credential provider, if it not throws a ForbiddenException
   *  + Check whether password is correct, if not throws a ForbiddenException
   *  + Check new password and confirmation are the same, if ther are not throws a BadRequestException
   *  + Check old password and new password are the same, if they are same, throw a BadRequestExcetion
   *  + Call transaction to update password and revoke all token
   *  + Clear cookies for web
   * @param response to clear cookies for web
   * @param request get user from token
   * @param changePasswordDTO contains oldPassword, newPassword, and confirmNewPassword
   * @returns HttpResponse with messages
   */
  async changePassword(
    response: Response,
    currentUser: AuthUser,
    changePasswordDTO: ChangePasswordDTO,
  ) {
    const { email } = currentUser;
    // check whether user's account is credential provider, if it not throws a ForbiddenException
    const oAuthAccountFounded =
      await this.userRepo.findOAuthAccountByproviderAccountId(email);
    if (!oAuthAccountFounded) {
      throw new ForbiddenException(message.user.not_support_change_password);
    }
    const userFounded = await this.userRepo.findUserByEmail(
      oAuthAccountFounded.user.email,
    );
    if (!userFounded || !userFounded.hashedpassword) {
      throw new ForbiddenException(message.user.not_support_change_password);
    }
    const { oldPassword, newPassword, confirmNewPassword } = changePasswordDTO;

    //check new password and confirmation are the same, if ther are not throws a BadRequestException
    if (newPassword !== confirmNewPassword) {
      throw new BadRequestException(message.user.confirm_password_not_match);
    }
    //check old password and new password are the same, if they are same, throw a BadRequestExcetion
    if (oldPassword === newPassword) {
      throw new BadRequestException(message.user.must_not_same_password);
    }
    // check whether password is correct, if not throws a ForbiddenException
    const isCorrectPassword = await HashHelper.compare(
      oldPassword,
      userFounded.hashedpassword,
    );
    if (!isCorrectPassword) {
      throw new ForbiddenException(message.user.invalid_credentials);
    }
    //call transaction to update password and revoke all token
    const userEntity: UserEntity = {
      ...userFounded,
      hashedpassword: await HashHelper.hash(newPassword),
    };
    await this.userRepo.resetPasswordAndRevokeAllRefreshToken(userEntity);
    //clear cookies for web
    response.clearCookie(cookieOptions.name.accessToken);
    response.clearCookie(cookieOptions.name.refreshToken);
    response.clearCookie(cookieOptions.name.sessionId);
    return sendResponse(
      HttpStatus.OK,
      message.user.change_password_successfully,
    );
  }

  async getProfile(currentUser: AuthUser) {
    const { email } = currentUser;
    //check whether user exist, if not throw a ForbiddenException
    const userFounded = await this.userRepo.findUserByEmail(email);
    if (!userFounded) {
      throw new UnauthorizedException(message.user.invalid_payload_token);
    }
    //get all signin method
    const allSignInMethod =
      await this.userRepo.getOAuthAccountProviderByUser(userFounded);
    const profile = {
      username: userFounded.username,
      email: userFounded.email,
      roles: userFounded.roles.map((role) => role.name),
      linkedAccounts: allSignInMethod.map(
        (oAuthAccount) => oAuthAccount.provider,
      ),
    };
    return sendResponse(
      HttpStatus.OK,
      message.user.get_profile_successfully,
      profile,
    );
  }
}
