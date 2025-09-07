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
import { AccountRepository } from './account.repository';
import { HashHelper } from '../common/helper/hash.helper';
import { AuthUser } from '../token/authuser.interface';
import { sendResponse } from '../common/helper/response.helper';
import { cookieOptions, message } from '../common/constants.common';
import { PostHobbiesDTO } from './dto/posthobbies.dto';
import { HobbyEntity } from './entity/hobby.entity';
import { UpdateUserNameDTO } from './dto/updateusername.dto';

@Injectable()
export class AccountService {
  constructor(private readonly accountRepo: AccountRepository) {}
  /**
   * Change password process:
   *  + Check whether user's account is credential provider, if it not throws a ForbiddenException
   *  + Check user ban status, if false throws a UnauthorizedException
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
      await this.accountRepo.findOAuthAccountByproviderAccountId(email);
    if (!oAuthAccountFounded) {
      throw new ForbiddenException(message.user.not_support_change_password);
    }
    const userFounded = await this.accountRepo.findUserByEmail(
      oAuthAccountFounded.user.email,
    );
    if (!userFounded || !userFounded.hashedpassword) {
      throw new ForbiddenException(message.user.not_support_change_password);
    }
    if (!userFounded.isActive) {
      throw new UnauthorizedException(message.user.not_active);
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
    await this.accountRepo.resetPasswordAndRevokeAllRefreshToken(userEntity);
    //clear cookies for web
    response.clearCookie(cookieOptions.name.accessToken);
    response.clearCookie(cookieOptions.name.refreshToken);
    response.clearCookie(cookieOptions.name.sessionId);
    return sendResponse(
      HttpStatus.OK,
      message.user.change_password_successfully,
    );
  }
  /**
   * get profile process:
   * +check whether user exist, if not throw a UnauthorizedException
   * +check user ban status, if false throws a UnauthorizedException
   * +get all signin methods of user
   * @param currentUser user auth token
   * @returns response with profile user
   */
  async getProfile(currentUser: AuthUser) {
    const { email } = currentUser;
    //check whether user exist, if not throw a UnauthorizedException
    const userFounded = await this.accountRepo.findUserByEmail(email);
    if (!userFounded) {
      throw new UnauthorizedException(message.user.invalid_payload_token);
    }
    //check user ban status, if false throws a UnauthorizedException
    if (!userFounded.isActive) {
      throw new UnauthorizedException(message.user.not_active);
    }
    const profile = {
      username: userFounded.username,
      email: userFounded.email,
      roles: userFounded.roles.map((role) => role.name),
      linkedAccounts: userFounded.oauthAccounts.map(
        (oAuthAccount) => oAuthAccount.provider,
      ),
      hobbies: userFounded.hobbies.map((hobby) => hobby.name),
      cefrLevel: userFounded.cefrLevel?.name,
    };
    return sendResponse(
      HttpStatus.OK,
      message.user.get_profile_successfully,
      profile,
    );
  }
  /**
   * get all hobbies:
   * @returns all hobbies can be selected
   */
  async getHobbies() {
    //get all hobbies
    const allHobbies = await this.accountRepo.getAllHobbies();
    return sendResponse(
      HttpStatus.OK,
      message.user.get_hobbies_successfully,
      allHobbies,
    );
  }
  /**
   * update hobbie:
   * @param currentUser user auth from token
   * @param postHobbies data from client contains array of hobbies
   * check whether user exist, if not throws a UnauthorizedException
   * check user ban status, if false throws a UnauthorizedException
   * check exist each hobby is array hobbies, if there is any hobby not exist throw a BadRequestException
   * @returns update user hobbies and send response
   */
  async updateHobbies(currentUser: AuthUser, postHobbies: PostHobbiesDTO) {
    //check whether user exist, if not throw a UnauthorizedException
    const { email } = currentUser;
    const userFound = await this.accountRepo.findUserByEmail(email);
    if (!userFound) {
      throw new UnauthorizedException(message.user.invalid_payload_token);
    }
    //check user ban status, if false throws a UnauthorizedException
    if (!userFound.isActive) {
      throw new UnauthorizedException(message.user.not_active);
    }
    const { hobbies } = postHobbies;
    //get unique elements from array
    const hobbiesUnique = Array.from(new Set(hobbies));
    //get HobbyEntity[] by mapping
    const hobbiesEntities: HobbyEntity[] = hobbiesUnique.map((hobby) => {
      return {
        id: hobby.id,
        name: hobby.name,
      } as HobbyEntity;
    });
    //check exist each hobby is array hobbies, if there is any hobby not exist throw a BadRequestException
    const hobbiesFoundCount =
      await this.accountRepo.countExistHobbies(hobbiesEntities);
    if (hobbiesFoundCount !== hobbies.length) {
      throw new BadRequestException(message.user.not_found_some_hobbies);
    }
    //save hobbies
    const userSave: UserEntity = {
      ...userFound,
      hobbies: hobbiesEntities,
    };
    await this.accountRepo.saveHobbies(userSave);
    return sendResponse(
      HttpStatus.OK,
      message.user.update_hobbies_successfully,
    );
  }
  /**
   * update user name:
   * @param currentUser user auth from token
   * @param updateUserNameDTO contains user name
   * @returns message
   */
  async updateUserName(
    currentUser: AuthUser,
    updateUserNameDTO: UpdateUserNameDTO,
  ) {
    const { sub } = currentUser;
    //update user name
    const { username } = updateUserNameDTO;
    await this.accountRepo.updateUserNameByID(sub, username);
    return sendResponse(HttpStatus.OK, 'Update user name successfully');
  }
}
