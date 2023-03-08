import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class UpdateGroupDto {
  @ApiProperty({
    type: String,
  })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  @IsOptional()
  profile?: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({
    type: String,
  })
  @IsString()
  @IsOptional()
  avatar?: string;
}
