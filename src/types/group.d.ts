import * as mongoose from 'mongoose';

import { ERoleGroup } from '@/types/enums/ERoleGroup';

export interface IGroupMember {
  userId: mongoose.Schema.Types.ObjectId;
  role: ERoleGroup;
}
