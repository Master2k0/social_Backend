import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class RegisterAuthDto {
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
