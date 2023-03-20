import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

import { IUser } from '@/modules/users/interfaces/user.interfaces';

export class UpdateUserDto implements Partial<IUser> {
  @ApiProperty()
  @IsOptional()
  @IsString()
  // @IsNotEmpty()
  firstName?: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  // @IsNotEmpty()
  lastName?: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  // @IsNotEmpty()
  phone?: string;

  @IsOptional()
  @IsString()
  refreshToken?: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  isVerified?: boolean;
}
