import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

import { IGroup } from '@/modules/group/interfaces/group.interfaces';

export class CreateGroupDto implements Partial<IGroup> {
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
