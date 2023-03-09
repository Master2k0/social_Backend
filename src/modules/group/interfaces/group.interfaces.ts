import { GroupMember } from '@/modules/group/schema/group.schema';
import { User } from '@/modules/users/schema/users.schema';
import { IEntity } from '@/types/common';
import { ERoleGroup } from '@/types/enums/ERoleGroup';
import { PropertyCustom } from '@/types/propertyCustomDocument';

export interface IGroup extends IEntity {
  createBy: PropertyCustom<User>;
  updateBy?: PropertyCustom<User>;
  name: string;
  metaTitle?: string;
  profile: string;
  description: string;
  avatar?: string;
  members: GroupMember[];
}

export type IGroupCreate = Partial<IGroup>;

export interface IGroupMemberUpdate {
  role: ERoleGroup;
  user: string;
}
