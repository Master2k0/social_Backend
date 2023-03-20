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
import { AccessTokenGuard } from '@/modules/auth/guards/accessToken.guard';
import { ITokenRequest } from '@/types/tokenRequest';
import convertToObject from '@/utils/convertToObject';

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

  @Post('register')
  @HttpCode(201)
  @ResponseMessage('Create user successfully')
  async register(@Body() body: RegisterAuthDto) {
    const newUser = await this.authService.register(body);
    return await plainToInstance(ResponseAuth, convertToObject(newUser));
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
  @ResponseMessage('Send email successfully')
  async forgotPassword(@Body() body: { mail: string }) {
    await this.authService.requestResetPassword(body.mail);
  }
}
