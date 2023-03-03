import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { plainToInstance } from 'class-transformer';

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
            return plainToInstance(dto, this.toObject());
          };
          return schema;
        },
      },
    ]),
  ],
  exports: [UsersService],
})
export class UsersModule {}
