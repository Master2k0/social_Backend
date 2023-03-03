import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class UpdateUserDto {
  @ApiProperty()
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  firstName?: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  lastName?: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  phone?: string;

  @IsOptional()
  @IsString()
  refreshToken?: string;
}
