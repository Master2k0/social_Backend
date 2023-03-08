import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Exclude } from 'class-transformer';
import { Document } from 'mongoose';

import { IUser } from '@/modules/users/interfaces/user.interfaces';

export type UserDocument = User & Document;

@Schema({
  timestamps: true,
  versionKey: false,
})
export class User implements IUser {
  name: string;
  isDeleted?: boolean;
  createdAt: Date;
  updatedAt?: Date;
  slug?: string;
  _id: string;

  @Prop({ type: String, required: true })
  firstName: string;

  @Prop({ type: String, required: true })
  lastName: string;

  @Prop({ type: String, required: true, unique: true })
  userName: string;

  @Prop({ type: String, required: true })
  @Exclude()
  password: string;

  @Prop({ type: String, required: true, unique: true })
  email?: string;

  @Prop()
  @Exclude()
  refreshToken?: string;

  toDto: (dto: any) => any;
}

export const UserSchema = SchemaFactory.createForClass(User);
