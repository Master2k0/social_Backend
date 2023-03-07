import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import { Document } from 'mongoose';

import { User } from '@/modules/users/schema/users.schema';
import { ERoleGroup } from '@/types/enums/ERoleGroup';

export type GroupDocument = Group & Document;

export class GroupMember {
  @Prop({ type: String, enum: ERoleGroup, required: true })
  role: ERoleGroup;
  @Prop({ type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' })
  user: User;
}

@Schema({
  timestamps: true,
  versionKey: false,
})
export class Group {
  _id: string;

  createBy: string;

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

  @Prop([GroupMember])
  members: GroupMember[];
  // | {
  //     role: ERoleGroup;
  //     user: mongoose.Schema.Types.ObjectId;
  //   };

  toDto: (dto: any) => any;
}

export const GroupSchema = SchemaFactory.createForClass(Group);
