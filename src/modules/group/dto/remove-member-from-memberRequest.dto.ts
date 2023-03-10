import { ApiProperty } from '@nestjs/swagger';
import { IsArray } from 'class-validator';

export class RemoveMemberFromGroupDto {
  @ApiProperty({ type: [String] })
  @IsArray()
  listIdUser: [string];
}
