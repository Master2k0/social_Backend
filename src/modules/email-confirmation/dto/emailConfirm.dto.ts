import { IsNotEmpty, IsString } from 'class-validator';

export class ConfirmEmailDto {
  @IsString()
  @IsNotEmpty()
  token: string;
}

export default ConfirmEmailDto;
