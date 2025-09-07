import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AccountService } from './account.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../role/role.guard';
import { Response } from 'express';
import { ChangePasswordDTO } from './dto/changepassword.dto';
import {
  ApiBadRequestResponse,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { CurrentUser } from '../token/currentuser.decorator';
import { AuthUser } from '../token/authuser.interface';
import { PostHobbiesDTO } from './dto/posthobbies.dto';
import { ValidUser } from '../common/guard/validuser.guard';
import { UserThrottlerGuard } from '../common/guard/throttler.guard';
import { UpdateUserNameDTO } from './dto/updateusername.dto';

@Controller('account')
@ApiTags('account')
@UseGuards(AuthGuard('jwt'), UserThrottlerGuard, RolesGuard)
@ApiUnauthorizedResponse({ description: 'Unauthorized user' })
export class AccountController {
  constructor(private accountService: AccountService) {}
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Change password',
    description:
      'Change password (only for credential) and revoke all refresh token',
  })
  @ApiOkResponse({
    description:
      'Change password successfully and clear access and refresh token, sessionid(web automatically), revoke all refreshtoken, Require the frontend to redirect the user to re-login.',
  })
  @ApiForbiddenResponse({
    description:
      'User account not credential provider/ Old password is invalid',
  })
  @ApiBadRequestResponse({
    description:
      'New password and its confirmation not same/ Old password and new password are the same',
  })
  @Post('changepassword')
  async changePassword(
    @Res({ passthrough: true }) response: Response,
    @CurrentUser() currentUser: AuthUser,
    @Body() changePasswordDTO: ChangePasswordDTO,
  ) {
    return this.accountService.changePassword(
      response,
      currentUser,
      changePasswordDTO,
    );
  }

  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get user profile' })
  @ApiOkResponse({ description: 'Get user profile successfully' })
  @Get('getprofile')
  async getProfile(@CurrentUser() currentUser: AuthUser) {
    return await this.accountService.getProfile(currentUser);
  }

  @UseGuards(ValidUser)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get all hobbies',
    description: 'Retrieve the list of available hobbies for selection.',
  })
  @ApiOkResponse({ description: 'Hobby list retrieved successfully.' })
  @Get('gethobbies')
  async getHobbies() {
    return await this.accountService.getHobbies();
  }

  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Update user hobbies' })
  @ApiOkResponse({ description: 'Hobbies updated successfully.' })
  @ApiBadRequestResponse({
    description: 'One or more specified hobbies do not exist.',
  })
  @Post('updatehobbies')
  async updateHoobies(
    @CurrentUser() currentUser: AuthUser,
    @Body() postHobbies: PostHobbiesDTO,
  ) {
    return await this.accountService.updateHobbies(currentUser, postHobbies);
  }

  @UseGuards(ValidUser)
  @HttpCode(HttpStatus.OK)
  @Post('updateusername')
  @ApiOperation({ summary: 'Update username' })
  @ApiOkResponse({ description: 'Username updated successfully.' })
  async updateUserName(
    @CurrentUser() currentUser: AuthUser,
    @Body() updateUserNameDTO: UpdateUserNameDTO,
  ) {
    return await this.accountService.updateUserName(
      currentUser,
      updateUserNameDTO,
    );
  }
}
