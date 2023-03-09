import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { plainToInstance } from 'class-transformer';

import convertToObject from '@/utils/convertToObject';

import { User, UserSchema } from './schema/users.schema';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

@Module({
  controllers: [UsersController],
  providers: [UsersService],
  imports: [
    MongooseModule.forFeatureAsync([
      {
        name: User.name,
        useFactory: () => {
          const schema = UserSchema;
          schema.methods.toDto = function (dto: any) {
            return plainToInstance(dto, convertToObject(this));
          };
          return schema;
        },
      },
    ]),
  ],
  exports: [UsersService],
})
export class UsersModule {}
