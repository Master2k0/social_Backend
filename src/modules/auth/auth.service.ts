import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import { UsersService } from '@/modules/users/users.service';
import { comparePassword, hashPassword } from '@/utils/hashPassword';

import { RegisterAuthDto } from './dto/register-auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async login(userName: string, password: string): Promise<any> {
    const user = await this.userService.findByUserName(userName);
    await this.verifyPassword(password, user.password);

    const tokens = await this.getTokens(user._id);
    await this.updateRefreshToken(user._id, tokens.refreshToken);
    return tokens;
  }

  async register(registrationData: RegisterAuthDto): Promise<any> {
    const newPassword = await hashPassword(registrationData.password);
    const registerUser = await this.userService.create({
      ...registrationData,
      password: newPassword,
    });
    return registerUser;
  }

  async logOut(userId: string) {
    await this.userService.update(userId, {
      refreshToken: null,
    });
  }

  async refreshToken(userId: string, refreshToken: string) {
    const user = await this.userService.findById(userId);
    if (!user || !user.refreshToken)
      throw new ForbiddenException('Access denied');
    if (!this.compareRefreshToken(refreshToken, user.refreshToken))
      throw new ForbiddenException('Access denied');

    const tokens = await this.getTokens(userId);
    await this.updateRefreshToken(userId, tokens.refreshToken);
    return tokens;
  }

  private async verifyPassword(
    plainTextPassword: string,
    hashedPassword: string,
  ) {
    const isMatching = await comparePassword(plainTextPassword, hashedPassword);
    if (!isMatching)
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: 'Password is incorrect',
        },
        HttpStatus.BAD_REQUEST,
      );
  }

  private async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await this.hashToken(refreshToken);
    console.log(userId);
    await this.userService.update(userId, {
      refreshToken: hashedRefreshToken,
    });
  }

  private async getTokens(userId: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          id: userId,
        },
        {
          secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
          expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRE_TIME'),
        },
      ),
      this.jwtService.signAsync(
        {
          id: userId,
        },
        {
          secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
          expiresIn: this.configService.get('JWT_REFRESH_TOKEN_EXPIRE_TIME'),
        },
      ),
    ]);
    return {
      accessToken,
      refreshToken,
    };
  }

  private async hashToken(token: string) {
    const salt = bcrypt.genSaltSync(10);
    const hashedToken = await bcrypt.hash(token, salt);
    return hashedToken;
  }

  private compareRefreshToken = async (
    refreshToken,
    refreshTokenStore,
  ): Promise<boolean> => {
    return await bcrypt.compare(refreshToken, refreshTokenStore);
  };
}
