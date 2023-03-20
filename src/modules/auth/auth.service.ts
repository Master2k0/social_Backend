import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { createHash } from 'crypto';

import { MailService } from '@/modules/mail/mail.service';
import { UsersService } from '@/modules/users/users.service';
import { comparePassword } from '@/utils/hashPassword';

import { RegisterAuthDto } from './dto/register-auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
  ) {}

  async login(userName: string, password: string): Promise<any> {
    const user = await this.userService.findByUserName(userName);
    if (!user.isVerified) {
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: 'Email is not verified',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
    await this.verifyPassword(password, user.password);

    const tokens = await this.getTokens(user._id);
    await this.updateRefreshToken(user._id, tokens.refreshToken);
    return tokens;
  }

  async register(registrationData: RegisterAuthDto): Promise<any> {
    const registerUser = await this.userService.create(registrationData);
    const tokens = await this.getVerifyToken(registerUser._id);
    try {
      await this.mailService.sendVerifyEmail(registerUser, tokens);
    } catch (e) {
      console.log(e);
    }
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
    const isMatching = await this.compareRefreshToken(
      refreshToken,
      user.refreshToken,
    );
    if (!isMatching) {
      throw new ForbiddenException('Access denied');
    }

    const tokens = await this.getTokens(userId);
    await this.updateRefreshToken(userId, tokens.refreshToken);
    return tokens;
  }

  async verifyEmail(token: string) {
    const { id } = await this.jwtService.verifyAsync(token, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
    });
    const user = await this.userService.findById(id);
    if (!user) {
      throw new ForbiddenException('Access denied');
    }
    if (user.isVerified) {
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: 'Email is already verified',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
    await this.userService.update(id, {
      isVerified: true,
    });
  }

  async requestResetPassword(email: string) {
    const user = await this.userService.findByEmail(email);
    const tokens = await this.getVerifyToken(user._id);
    try {
      await this.mailService.sendResetPassword(user, tokens);
    } catch (e) {
      console.log(e);
    }
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

  private async getVerifyToken(userId: string) {
    return await this.jwtService.signAsync(
      {
        id: userId,
      },
      {
        secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      },
    );
  }

  private async hashToken(token: string) {
    const salt = bcrypt.genSaltSync(10);
    // ? https://stackoverflow.com/questions/64470962/why-refresh-endpoint-return-new-tokens-when-i-use-old-refresh-token
    const hash = createHash('sha256').update(token).digest('hex');
    // //////////////
    const hashedToken = await bcrypt.hash(hash, salt);
    return hashedToken;
  }

  private compareRefreshToken = async (
    refreshToken,
    refreshTokenStore,
  ): Promise<boolean> => {
    const hash = createHash('sha256').update(refreshToken).digest('hex');
    return await bcrypt.compare(hash, refreshTokenStore);
  };
}
