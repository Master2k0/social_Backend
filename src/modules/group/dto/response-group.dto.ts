import { Exclude } from 'class-transformer';

import { User } from '@/modules/users/schema/users.schema';
import { PropertyCustom } from '@/types/propertyCustomDocument';

export class ResponseGroup {
  @Exclude()
  membersRequest: PropertyCustom<User>[];
}
