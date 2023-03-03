import { Prop, Schema } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import { Document } from 'mongoose';

import { User } from '@/modules/users/schema/users.schema';
import { ERoleGroup } from '@/types/enums/ERoleGroup';

export type GroupDocument = Group & Document;

export class GroupMember {
  @Prop()
  role: ERoleGroup;
  @Prop({ type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' })
  userId: User;
}

@Schema({
  timestamps: true,
  versionKey: false,
})
export class Group {
  _id: string;

  // @Prop({ type: String, required: true })
  createBy: string;

  // @Prop
  updateBy?: string;

  @Prop({ type: String, required: true })
  name: string;

  @Prop({ type: String, required: true })
  slug: string;

  @Prop({ type: String })
  metaTitle?: string;

  @Prop({ type: String, required: true })
  profile: string;

  @Prop({ type: String, required: true })
  description: string;

  @Prop({ type: String })
  avatar?: string;

  @Prop({ type: [GroupMember] })
  members: GroupMember[];
}
