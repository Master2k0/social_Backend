export interface IEntity {
  _id?: string;
  isDeleted?: boolean;
  createdAt?: Date;
  updatedAt?: Date;
  slug?: string;
}
export interface ICommonRequest {
  id: string;
}
