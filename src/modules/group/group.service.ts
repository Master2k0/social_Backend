import { Injectable } from '@nestjs/common';

import { GroupDocument } from '@/modules/group/schema/group.schema';

import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';

@Injectable()
export class GroupService {
  create(idUserCreate: string, createGroupDto: CreateGroupDto) {
    // const payload: GroupDocument = {
    //   createBy: idUserCreate,
    //   name: createGroupDto.name,
    //   profile: createGroupDto.profile,
    //   description: createGroupDto.description,
    //   avatar: createGroupDto?.avatar || '',

    // };
    return 'This action adds a new group';
  }

  findAll() {
    return `This action returns all group`;
  }

  findOne(id: number) {
    return `This action returns a #${id} group`;
  }

  update(id: number, updateGroupDto: UpdateGroupDto) {
    return `This action updates a #${id} group`;
  }

  remove(id: number) {
    return `This action removes a #${id} group`;
  }
}
