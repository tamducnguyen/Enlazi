import {
  Controller,
  Res,
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
import { SignUpDTO } from './dto/auth.singup.dto';
import { SignInDTO } from './dto/auth.singin.dto';
import { VerifyDTO } from './dto/auth.verify.dto';
import { RefreshDTO } from './dto/auth.refresh.dto';
import { SignOutDTO } from './dto/auth.signout.dto';
import { ForgotPasswordDTO } from './dto/auth.forgotpassword.dto';
import { VerifyForgotPasswordDTO } from './dto/auth.verifyforgpass.dto';
import { UserThrottlerGuard } from '../common/guard/throttler.guard';
import { GoogleAuthService } from './oauth/google.service';
import { RefreshTokenGuard } from '../token/refresh.jwt.guard';
import { ExchangeCodeDTO } from './dto/auth.exchangecode.dto';
import { CurrentUser } from '../token/currentuser.decorator';
import { AuthUser } from '../token/authuser.interface';

@ApiTags('auth')
@Controller('auth')
@UseGuards(UserThrottlerGuard)
@ApiTooManyRequestsResponse({ description: 'Too many request!' })
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly googleAuthService: GoogleAuthService,
  ) {}

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  @SkipThrottle({ low: true })
  @ApiOperation({
    summary: 'Register a new user account',
    description: 'Send verify code via email',
  })
  @ApiCreatedResponse({ description: 'Sent mail successfully to verify user' })
  @ApiBadRequestResponse({
    description: 'Email already exist! / Wait before resend',
  })
  async signUp(@Body() signUpDTO: SignUpDTO) {
    return await this.authService.signUp(signUpDTO);
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
      ' User already exist/ User send invalid infor / User got banned/ User send incorrect code ',
  })
  async verify(@Body() verifyDTO: VerifyDTO) {
    return await this.authService.verifyUser(verifyDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
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
  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  @ApiOperation({
    summary: 'Refresh the access token using a valid refresh token',
    description: 'Get refresh token and session id from headers and cookies',
  })
  @ApiOkResponse({
    description:
      'New access token is sent through cookies(web automatically), remove the old one(web automatically)',
  })
  @ApiUnauthorizedResponse({ description: 'Refresh token are invalid' })
  async refresh(
    @Res({ passthrough: true }) response: Response,
    @CurrentUser() currentUser: AuthUser,
    @Body() refreshDTO: RefreshDTO,
  ) {
    return await this.authService.refresh(response, currentUser, refreshDTO);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(RefreshTokenGuard)
  @Post('signout')
  @ApiOperation({
    summary:
      'Sign out and revoke the current user session id and refresh token through headers and cookie',
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
    @Body() signOutDTO: SignOutDTO,
  ) {
    return await this.authService.signOut(res, signOutDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('forgotpassword')
  @SkipThrottle({ low: true })
  @ApiOperation({
    summary: 'Initiate password reset process by sending a reset code',
  })
  @ApiOkResponse({ description: 'Send verify code successfully via mail' })
  @ApiBadRequestResponse({
    description:
      'User not exist/ User not active / User got banned/ Wait before resend',
  })
  async forgotPassword(@Body() forgotPasswordDTO: ForgotPasswordDTO) {
    return this.authService.forgotPassword(forgotPasswordDTO);
  }

  @HttpCode(HttpStatus.OK)
  @Post('verifyforgotpassword')
  @ApiOperation({ summary: 'Verify reset code and update the user password' })
  @ApiOkResponse({
    description:
      'Reset password sucessfully, clear access and refresh token, sessionId cookies(web automatically) ',
  })
  @ApiBadRequestResponse({
    description:
      'User not exist / User send invalid verefy code/ User got banned',
  })
  async verifyForgotPassword(
    @Res({ passthrough: true }) res: Response,
    @Body() verifyFPDTO: VerifyForgotPasswordDTO,
  ) {
    return this.authService.verifyAndResetPassword(res, verifyFPDTO);
  }
  @Post('signin/google')
  @ApiOperation({ summary: 'Sign in or sign up with Google account' })
  @ApiOkResponse({
    description:
      'User sign in with Google account successfully, Send access token(1h), refresh token(1y), and session id through cookies(only web) and body',
  })
  @ApiUnauthorizedResponse({
    description:
      'Google did not return id_token, Invalid Google Token, Email is not verified by Google',
  })
  @ApiInternalServerErrorResponse({ description: 'Code is invalid' })
  @SkipThrottle({ burst: true })
  async exchangeCode(
    @Res({ passthrough: true }) response: Response,
    @Body() exchangeCode: ExchangeCodeDTO,
  ) {
    return await this.googleAuthService.exchangeCodeForTokens(
      response,
      exchangeCode,
    );
  }
}
