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
import { UsersService } from '@/modules/users/users.service';
import { ITokenRequest } from '@/types/tokenRequest';

import { EmailConfirmationService } from '../email-confirmation/email-confirmation.service';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { ResponseAuth } from './dto/response-auth.dto';
import { RefreshTokenGuard } from './guards/refreshToken.guard';

@ApiTags('authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UsersService,
    private readonly emailConfirmationService: EmailConfirmationService,
  ) {}

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
    const newUser = await this.userService.create(body);
    await this.emailConfirmationService.sendVerificationLink(body.email);
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
}
