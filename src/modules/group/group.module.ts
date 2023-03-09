import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { plainToInstance } from 'class-transformer';

import { UsersModule } from '@/modules/users/users.module';
import convertToObject from '@/utils/convertToObject';

import { GroupController } from './group.controller';
import { GroupService } from './group.service';
import { Group, GroupSchema } from './schema/group.schema';

@Module({
  controllers: [GroupController],
  providers: [GroupService],
  imports: [
    MongooseModule.forFeatureAsync([
      {
        name: Group.name,
        useFactory: () => {
          const schema = GroupSchema;
          schema.methods.toDto = function (dto: any) {
            return plainToInstance(dto, convertToObject(this));
          };
          return schema;
        },
      },
    ]),
    UsersModule,
  ],

  exports: [GroupService],
})
export class GroupModule {}
