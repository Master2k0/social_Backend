import { Exclude } from 'class-transformer';

export class ResponseAuth {
  @Exclude()
  password: string;

  @Exclude()
  refreshToken: string;
}
