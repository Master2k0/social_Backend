import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { AccessTokenStrategy } from '@/modules/auth/strategies/accessToken.strategy';
import { RefreshTokenStrategy } from '@/modules/auth/strategies/refreshToken.strategy';
import { UsersModule } from '@/modules/users/users.module';

import { EmailConfirmationModule } from '../email-confirmation/email-confirmation.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    ConfigModule,
    JwtModule.register({}),
    EmailConfirmationModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, AccessTokenStrategy, RefreshTokenStrategy],
  exports: [AuthService],
})
export class AuthModule {}
