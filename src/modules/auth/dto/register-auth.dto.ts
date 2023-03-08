import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

import { IUser } from '@/modules/users/interfaces/user.interfaces';

export class RegisterAuthDto implements Partial<IUser> {
  @ApiProperty({
    type: String,
  })
  @IsString()
  userName: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  password: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  @IsOptional()
  email?: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  firstName: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  lastName: string;
}
