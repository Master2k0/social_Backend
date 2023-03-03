import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { plainToInstance } from 'class-transformer';

import { LoginAuthDto } from '@/modules/auth/dto/login-auth.dto';
import { AccessTokenGuard } from '@/modules/auth/guards/accessToken.guard';
import { UsersService } from '@/modules/users/users.service';
import { ITokenRequest } from '@/types/tokenRequest';

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
  ) {}

  @Post('login')
  async login(@Req() req, @Body() body: LoginAuthDto) {
    return await this.authService.login(body.userName, body.password);
  }

  @Post('register')
  async register(@Res() response, @Body() body: RegisterAuthDto) {
    try {
      const newUser = await this.userService.create(body);
      return response.status(HttpStatus.CREATED).json({
        message: 'Create user successfully',
        data: plainToInstance(ResponseAuth, newUser.toObject()),
      });
    } catch (err) {
      let message = 'Bad request';
      if (err?.code === 11000) {
        message = 'User already exists';
      } else {
        message = err?._message;
      }
      throw new BadRequestException('Something bad happened', {
        cause: new Error(),
        description: message,
      });
    }
  }

  @Get('logout')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  async logout(@Req() req: ITokenRequest) {
    this.authService.logOut(req.user.id);
  }

  @Get('refresh')
  @UseGuards(RefreshTokenGuard)
  @ApiBearerAuth('JWT-auth')
  async refreshTokens(@Req() req: ITokenRequest) {
    const userId = req.user.id;
    const refreshToken = req.user.refreshToken;
    return await this.authService.refreshToken(userId, refreshToken);
  }
}
