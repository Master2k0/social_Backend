import { Module } from '@nestjs/common';

import { EmailModule } from '../email/email.module';
import { EmailConfirmationService } from './email-confirmation.service';

@Module({
  imports: [EmailModule],
  providers: [EmailConfirmationService],
})
export class EmailConfirmationModule {}
