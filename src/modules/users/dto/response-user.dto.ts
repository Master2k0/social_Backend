import { Exclude } from 'class-transformer';

export class ResponseUser {
  @Exclude()
  password: string;

  @Exclude()
  refreshToken: string;
}
