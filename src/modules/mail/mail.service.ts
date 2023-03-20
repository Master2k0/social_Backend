import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

import { User } from '@/modules/users/schema/users.schema';

@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}

  async sendVerifyEmail(user: User, token: string) {
    const url = `${process.env.EMAIL_USER_CONFIRMATION}=${token} `;
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Welcome to H!Mount! Confirm your Email',
      template: './confirmation',
      context: {
        name: user.firstName,
        url,
      },
    });
  }

  async sendResetPassword(user: User, token: string) {
    const url = `${process.env.EMAIL_RESET_PASSWORD}=${token} `;
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Reset your password',
      template: './resetPassword',
      context: {
        name: user.firstName,
        url,
      },
    });
  }
}
