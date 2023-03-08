import { HttpException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { ObjectId } from 'mongodb';
import { Model } from 'mongoose';

import { IGroupCreate } from '@/modules/group/interfaces/group.interfaces';
import { Group, GroupDocument } from '@/modules/group/schema/group.schema';
import { ERoleGroup } from '@/types/enums/ERoleGroup';

import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';

@Injectable()
export class GroupService {
  constructor(
    @InjectModel(Group.name) private readonly model: Model<GroupDocument>,
  ) {}
  async create(idUserCreate: string, createGroupDto: CreateGroupDto) {
    const payload: IGroupCreate = {
      createBy: new ObjectId(idUserCreate),
      updateBy: new ObjectId(idUserCreate),
      name: createGroupDto.name,
      profile: createGroupDto.profile,
      description: createGroupDto.description,
      avatar: createGroupDto?.avatar || '',
      members: [
        {
          role: ERoleGroup.ADMIN,
          user: new ObjectId(idUserCreate),
        },
      ],
    };
    const newGroup = await this.model.create(payload);
    const group = await this.model
      .findById(newGroup.id)
      .populate({
        path: 'members',
        populate: {
          path: 'user',
          model: 'User',
          select: 'firstName lastName',
        },
      })
      .populate({
        path: 'createBy',
        model: 'User',
        select: 'firstName lastName',
      })
      .populate({
        path: 'updateBy',
        model: 'User',
        select: 'firstName lastName',
      })
      .exec();
    return group;
  }

  async update(
    idAdmin: string,
    idGroup: string,
    updateGroupDto: UpdateGroupDto,
  ) {
    await this.checkPermission(idAdmin, idGroup);
    const res = await this.model
      .findOneAndUpdate(
        { _id: idGroup },
        {
          ...updateGroupDto,
          updateBy: new ObjectId(idAdmin),
        },
        { new: true },
      )
      .exec();
    return res;
  }

  findAll() {
    return `This action returns all group`;
  }

  async findBySlug(slug: string) {
    const group = await this.model
      .findOne({ slug })
      .populate({
        path: 'members',
        populate: {
          path: 'user',
          model: 'User',
          select: 'name firstName lastName',
        },
      })
      .populate({
        path: 'createBy',
        model: 'User',
        select: 'name firstName lastName',
      })
      .populate({
        path: 'updateBy',
        model: 'User',
        select: 'name firstName lastName',
      })
      .exec();

    return group;
  }

  async checkPermission(idUser: string, idGroup: string) {
    const group = await this.model.findById(idGroup).populate({
      path: 'members',
      populate: {
        path: 'user',
        model: 'User',
        select: '_id',
      },
    });
    if (!group) throw new HttpException('Group not found', 404);
    const isAdmin = group.members.find(
      (member) =>
        member.user?._id.toString() === idUser &&
        member.role === ERoleGroup.ADMIN,
    );
    if (!isAdmin) throw new HttpException('You are not admin', 403);
  }
  // update(id: number, updateGroupDto: UpdateGroupDto) {
  //   return `This action updates a #${id} group`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} group`;
  // }
}
