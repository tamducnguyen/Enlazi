import {
  Controller,
  Res,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
  Body,
  Post,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { SkipThrottle } from '@nestjs/throttler';
import {
  ApiBadRequestResponse,
  ApiCreatedResponse,
  ApiInternalServerErrorResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { SignUpDTO } from './dto/user.singup.dto';
import { SignInDTO } from './dto/user.singin.dto';
import { VerifyDTO } from './dto/user.verify.dto';
import { RefreshDTO } from './dto/users.refresh.dto';
import { SignOutDTO } from './dto/users.signout.dto';
import { SendVerifyCodeDTO } from './dto/users.sendverifycode.dto';
import { ForgotPasswordDTO } from './dto/users.forgotpassword.dto';
import { VerifyForgotPasswordDTO } from './dto/users.verifyforgpass.dto';
import { UserThrottlerGuard } from '../common/guard/user_throttler.guard';

@ApiTags('auth')
@Controller('auth')
@UseGuards(UserThrottlerGuard)
@ApiTooManyRequestsResponse({ description: 'Too many request!' })
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  @ApiOperation({
    summary: 'Register a new user account',
    description: 'Send verify code via email',
  })
  @ApiCreatedResponse({ description: 'Sent mail successfully to verify user' })
  @ApiBadRequestResponse({ description: 'Email already exist!' })
  @ApiInternalServerErrorResponse({
    description: 'Role is not exist',
  })
  async signUp(@Body() signUpDTO: SignUpDTO) {
    return await this.authService.signUp(signUpDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('sendverifycode')
  @ApiOperation({ summary: 'Resend a verification code to the user email' })
  @ApiOkResponse({ description: 'Send veriy code successfully via email' })
  @ApiBadRequestResponse({
    description: 'User not exist / User already verified',
  })
  async sendVerifycode(@Body() sendVerifycodeDTO: SendVerifyCodeDTO) {
    return await this.authService.sendVerifyCode(sendVerifycodeDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('verify')
  @SkipThrottle({ burst: true })
  @ApiOperation({
    summary: 'Verify a user account using the provided code via email',
  })
  @ApiOkResponse({ description: 'Verify successfully' })
  @ApiBadRequestResponse({
    description:
      'User not exist / User already verified / User send invalid verifycode / User got banned ',
  })
  async verify(@Body() verifyDTO: VerifyDTO) {
    return await this.authService.verifyUser(verifyDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  @SkipThrottle({ burst: true })
  @ApiOperation({
    summary: 'Authenticate user and issue access/refresh tokens',
  })
  @ApiOkResponse({
    description:
      'User sign in successfully, Send access token(1h), refresh token(1y), and session id through cookies(only web) and body',
  })
  @ApiBadRequestResponse({
    description: 'User not exist / User not verified / Wrong password',
  })
  async signIn(
    @Body() signInDTO: SignInDTO,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.signIn(signInDTO, res);
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  @SkipThrottle({ burst: true })
  @ApiOperation({
    summary: 'Refresh the access token using a valid refresh token',
    description: 'Get refresh token and session id from body',
  })
  @ApiOkResponse({
    description:
      'New access token is sent through cookies(web only), remove the old one(web automatically)',
  })
  @ApiUnauthorizedResponse({ description: 'Refresh token are invalid' })
  async refresh(
    @Res({ passthrough: true }) response: Response,
    @Req() request: Request,
    @Body() refreshDTO?: RefreshDTO,
  ) {
    return await this.authService.refresh(response, request, refreshDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signout')
  @SkipThrottle({ burst: true })
  @ApiOperation({
    summary:
      'Sign out and revoke the current user session id and refresh token',
  })
  @ApiOkResponse({
    description: 'Remove accesstoken and refreshtoken(web automatically)',
  })
  @ApiBadRequestResponse({ description: 'Invalid data posted' })
  @ApiUnauthorizedResponse({
    description: 'Invalid refresh token or sessionid',
  })
  async signOut(
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
    @Body() signOutDTO: SignOutDTO,
  ) {
    return await this.authService.signOut(res, req, signOutDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('forgotpassword')
  @ApiOperation({
    summary: 'Initiate password reset process by sending a reset code',
  })
  @ApiOkResponse({ description: 'Send verify code successfully via mail' })
  @ApiBadRequestResponse({ description: 'User not exist/ User not verified' })
  async forgotPassword(@Body() forgotPasswordDTO: ForgotPasswordDTO) {
    return this.authService.forgotPassword(forgotPasswordDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('verifyforgotpassword')
  @SkipThrottle({ burst: true })
  @ApiOperation({ summary: 'Verify reset code and update the user password' })
  @ApiOkResponse({
    description: 'Reset password sucessfully ',
  })
  @ApiBadRequestResponse({
    description:
      'User not exist / User send invalid verefy code/ User got banned',
  })
  async verifyForgotPassword(@Body() verifyFPDTO: VerifyForgotPasswordDTO) {
    return this.authService.verifyAndResetPassword(verifyFPDTO);
  }
}
