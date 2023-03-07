import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { plainToInstance } from 'class-transformer';

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
            return plainToInstance(dto, this.toObject());
          };
          return schema;
        },
      },
    ]),
  ],

  exports: [GroupService],
})
export class GroupModule {}
