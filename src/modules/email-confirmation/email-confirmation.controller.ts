import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Post,
  UseInterceptors,
} from '@nestjs/common';

import ConfirmEmailDto from './dto/emailConfirm.dto';
import { EmailConfirmationService } from './email-confirmation.service';

@Controller('email-confirmation')
@UseInterceptors(ClassSerializerInterceptor)
export class EmailConfirmationController {
  constructor(
    private readonly emailConfirmationService: EmailConfirmationService,
  ) {}

  //   @Post('confirm')
  //   async confirm(@Body() confirmationData: ConfirmEmailDto) {
  //     const email = await this.emailConfirmationService.decodeConfirmationToken(
  //       confirmationData.token,
  //     );
  //     await this.emailConfirmationService.confirmEmail(email);
  //   }
}
