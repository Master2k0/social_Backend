import { SetMetadata } from '@nestjs/common';

export const AllowAccessWithoutToken = () => SetMetadata('allow-any', true);
