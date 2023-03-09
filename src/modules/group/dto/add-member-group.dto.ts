import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class AddMemberRequestToGroupDto {
  @ApiProperty({ type: String })
  @IsString()
  idUser: string;
}
