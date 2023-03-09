import { ApiProperty } from '@nestjs/swagger';
import { IsArray, IsOptional } from 'class-validator';

import { IGroupMemberUpdate } from '@/modules/group/interfaces/group.interfaces';
import { ERoleGroup } from '@/types/enums/ERoleGroup';

class TGroupMemberUpdate implements IGroupMemberUpdate {
  @ApiProperty({ enum: ERoleGroup })
  role: ERoleGroup;
  @ApiProperty({ type: String })
  user: string;
}
export class UpdateMemberGroupDto {
  @ApiProperty({
    type: [TGroupMemberUpdate],
  })
  @IsOptional()
  @IsArray()
  members: IGroupMemberUpdate[];
}
