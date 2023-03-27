import { HttpService } from '@nestjs/axios';
import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { createHash } from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { firstValueFrom } from 'rxjs';

import { ResetPasswordDto } from '@/modules/auth/dto/reset-password-auth.dto';
import { MailService } from '@/modules/mail/mail.service';
import { CreateUserDto } from '@/modules/users/dto/create-user.dto';
import { User } from '@/modules/users/schema/users.schema';
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
    private readonly httpService: HttpService,
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
    const tokens = await this.getResetPasswordToken(user._id);
    try {
      await this.mailService.sendResetPassword(user, tokens);
    } catch (e) {
      console.log(e);
    }
  }

  async resetPassword(data: ResetPasswordDto): Promise<User> {
    if (data.password !== data.confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }
    const { id } = await this.jwtService.verifyAsync(data.token, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
    });
    const user = await this.userService.findById(id);
    if (!user) {
      throw new ForbiddenException('User not found');
    }

    const userHasNewPassword = await this.userService.updatePassword(
      id,
      data.password,
    );
    try {
      await this.mailService.sendResetPasswordSuccess(user);
    } catch (e) {
      console.log(e);
    }
    return userHasNewPassword;
  }

  async loginWithGithub(code: string) {
    const { data } = await firstValueFrom(
      this.httpService.post(
        `https://github.com/login/oauth/access_token?client_id=${process.env.GITHUB_CLIENT_ID}&client_secret=${process.env.GITHUB_CLIENT_SECRECT_KEY}&code=${code}`,
        {},
        {
          headers: {
            accept: 'application/json',
          },
        },
      ),
    );
    if (!data) throw new BadRequestException('Invalid github code');
    const { access_token } = data;
    const userData = await this.getDataUserGithub(access_token);
    let user: User;
    try {
      user = await this.userService.findByEmail(userData.email);
    } catch (err) {
      const payload: Omit<CreateUserDto, 'password'> = {
        firstName: userData.name,
        lastName: userData.name,
        email: userData.email,
        userName: userData.login,
        isVerified: true,
      };
      user = await this.userService.createUserWithoutPassword(payload);
    }
    const token = await this.getTokens(user._id);
    return token;
  }

  async getDataUserGithub(accessToken: string) {
    const { data } = await firstValueFrom(
      this.httpService.get(`https://api.github.com/user`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }),
    );
    return data;
  }

  async loginWithGoogle(code: string) {
    const oAuth2Client = new OAuth2Client(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      'postmessage',
    );
    const { tokens } = await oAuth2Client.getToken(code);
    const { data: userData } = await firstValueFrom(
      this.httpService.get('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      }),
    );
    if (!userData) throw new BadRequestException('Invalid google code');
    let user: User;
    try {
      user = await this.userService.findByEmail(userData.email);
    } catch (err) {
      const payload: Omit<CreateUserDto, 'password'> = {
        firstName: userData.given_name,
        lastName: userData.family_name,
        email: userData.email,
        userName: userData.email,
        isVerified: true,
      };
      user = await this.userService.createUserWithoutPassword(payload);
    }
    const token = await this.getTokens(user._id);
    return token;
  }

  async loginWithDiscord(code: string) {
    const { data } = await this.httpService.axiosRef.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_SECRET_ID,
        code,
        grant_type: 'authorization_code',
        scope: 'identify email',
        redirect_uri: 'http://localhost:2402/auth/discord',
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );
    const { access_token } = data;
    const { data: userDataReturn } = await this.httpService.axiosRef.get(
      'https://discord.com/api/users/@me',
      {
        headers: {
          authorization: `Bearer ${access_token}`,
        },
      },
    );
    let user: User;
    try {
      user = await this.userService.findByEmail(userDataReturn.email);
    } catch (err) {
      const payload: Omit<CreateUserDto, 'password'> = {
        firstName: userDataReturn.global_name || 'unknown',
        lastName: userDataReturn.username || 'unknown',
        email: userDataReturn.email,
        userName: userDataReturn.username,
        isVerified: true,
      };
      user = await this.userService.createUserWithoutPassword(payload);
    }
    const token = await this.getTokens(user._id);
    return token;
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

  private async getResetPasswordToken(userId: string) {
    return await this.jwtService.signAsync(
      {
        id: userId,
      },
      {
        secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
        expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRE_TIME'),
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
