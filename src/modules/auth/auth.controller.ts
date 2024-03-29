import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { plainToInstance } from 'class-transformer';

import { ResponseMessage } from '@/common/decorator/response.decorator';
import { LOGIN_SUCCESS } from '@/constants/messageResponse.constants';
import { LoginAuthDto } from '@/modules/auth/dto/login-auth.dto';
import { ResetPasswordDto } from '@/modules/auth/dto/reset-password-auth.dto';
import { AccessTokenGuard } from '@/modules/auth/guards/accessToken.guard';
import { ITokenRequest } from '@/types/tokenRequest';
import convertToObject from '@/utils/convertToObject';

// import { EmailConfirmationService } from '../email-confirmation/email-confirmation.service';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResponseAuth } from './dto/response-auth.dto';
import { RefreshTokenGuard } from './guards/refreshToken.guard';

@ApiTags('authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(201)
  @ResponseMessage(LOGIN_SUCCESS)
  async login(@Req() req, @Body() body: LoginAuthDto) {
    return await this.authService.login(body.userName, body.password);
  }

  @Post('github')
  @HttpCode(201)
  @ResponseMessage(LOGIN_SUCCESS)
  async githubLogin(@Req() req, @Body() body: { code: string }) {
    return await this.authService.loginWithGithub(body.code);
  }

  @Post('google')
  @HttpCode(201)
  @ResponseMessage(LOGIN_SUCCESS)
  async googleLogin(@Req() req, @Body() body: { code: string }) {
    return await this.authService.loginWithGoogle(body.code);
  }

  @Post('discord')
  @HttpCode(201)
  @ResponseMessage(LOGIN_SUCCESS)
  async discordLogin(@Body() body: { code: string }) {
    return await this.authService.loginWithDiscord(body.code);
  }

  @Post('register')
  @HttpCode(201)
  @ResponseMessage('Create user successfully')
  async register(@Body() body: RegisterAuthDto) {
    const newUser = await this.authService.register(body);
    return await plainToInstance(ResponseAuth, newUser.toObject());
  }

  @Get('logout')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Logout successfully')
  async logout(@Req() req: ITokenRequest) {
    this.authService.logOut(req.user.id);
  }

  @Get('refresh')
  @UseGuards(RefreshTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Refresh token successfully')
  async refreshTokens(@Req() req: ITokenRequest) {
    const userId = req.user.id;
    const refreshToken = req.user.refreshToken;
    return await this.authService.refreshToken(userId, refreshToken);
  }

  @Post('verify-email')
  @HttpCode(201)
  @ResponseMessage('Verify email successfully')
  async verifyEmail(@Body() body: { token: string }) {
    await this.authService.verifyEmail(body.token);
  }

  @Post('forgot-password')
  @HttpCode(201)
  @ResponseMessage('Request successfully')
  async forgotPassword(@Body() body: { email: string }) {
    await this.authService.requestResetPassword(body.email);
  }

  @Post('reset-password')
  @HttpCode(201)
  @ResponseMessage('Reset password successfully')
  async resetPassword(@Body() body: ResetPasswordDto) {
    const user = await this.authService.resetPassword(body);
    return await plainToInstance(ResponseAuth, convertToObject(user));
  }
}
