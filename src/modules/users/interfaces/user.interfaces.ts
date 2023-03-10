import { IEntity } from '@/types/common';

export interface IUser extends IEntity {
  firstName: string;
  lastName: string;
  userName: string;
  email?: string;
  password: string;
  refreshToken?: string;
}
