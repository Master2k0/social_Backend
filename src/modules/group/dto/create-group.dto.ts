import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class CreateGroupDto {
  @ApiProperty({
    type: String,
  })
  @IsString()
  name: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  profile: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  description: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  avatar?: string;
}
