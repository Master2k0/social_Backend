import { Request } from 'express';

interface IPropsTokenStrategy {
  id: string;
  accessToken?: string;
  refreshToken?: string;
}

export type ITokenRequest = Request & {
  user: IPropsTokenStrategy;
};
