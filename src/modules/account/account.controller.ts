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

@Controller('account')
@ApiTags('account')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@ApiUnauthorizedResponse({ description: 'Unauthorize user' })
export class AccountController {
  constructor(private usersService: AccountService) {}
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Change password',
    description:
      'Change password (only for credential) and revoke all refresh token',
  })
  @ApiOkResponse({
    description:
      'Change password successfully and clear access and refresh token, sessionid(web automatically), revoke all refreshtoken',
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
  async resetPassword(
    @Res({ passthrough: true }) response: Response,
    @CurrentUser() currentUser: AuthUser,
    @Body() changePasswordDTO: ChangePasswordDTO,
  ) {
    return this.usersService.changePassword(
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
    return await this.usersService.getProfile(currentUser);
  }
}
