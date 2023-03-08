import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import { Document } from 'mongoose';

import { IGroup } from '@/modules/group/interfaces/group.interfaces';
import { User } from '@/modules/users/schema/users.schema';
import { ERoleGroup } from '@/types/enums/ERoleGroup';
import { PropertyCustom } from '@/types/propertyCustomDocument';

export type GroupDocument = Group & Document;

export class GroupMember {
  @Prop({ type: String, enum: ERoleGroup, required: true })
  role: ERoleGroup;
  @Prop({ type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' })
  user: PropertyCustom<User>;
}

@Schema({
  timestamps: true,
  versionKey: false,
})
export class Group implements IGroup {
  _id: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' })
  createBy: PropertyCustom<User>;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  updateBy?: PropertyCustom<User>;

  @Prop({ type: String, required: true })
  name: string;

  @Prop({
    type: String,
    // required: true,
    unique: true,
    slug: 'name',
  })
  slug: string;

  @Prop({ type: String })
  metaTitle?: string;

  @Prop({ type: String, required: true })
  profile: string;

  @Prop({ type: String, required: true })
  description: string;

  @Prop({ type: String })
  avatar?: string;

  @Prop({ type: [Object] })
  members: GroupMember[];

  toDto: (dto: any) => any;
}

export const GroupSchema = SchemaFactory.createForClass(Group);
