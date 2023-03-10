import { HttpException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { ObjectId } from 'mongodb';
import { Model } from 'mongoose';

import {
  IGroup,
  IGroupCreate,
  IGroupMemberUpdate,
} from '@/modules/group/interfaces/group.interfaces';
import { Group, GroupDocument } from '@/modules/group/schema/group.schema';
import { UsersService } from '@/modules/users/users.service';
import { ERoleGroup } from '@/types/enums/ERoleGroup';

import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';
import { UpdateMemberGroupDto } from './dto/updateMember-group.dto';

@Injectable()
export class GroupService {
  constructor(
    @InjectModel(Group.name) private readonly model: Model<GroupDocument>,
    private readonly UserService: UsersService,
  ) {}
  async create(
    idUserCreate: string,
    createGroupDto: CreateGroupDto,
  ): Promise<IGroup> {
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

  async findBySlug(slug: string): Promise<GroupDocument> {
    const group = await this.model
      .findOne({ slug, isDeleted: false })
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
      });
    if (!group) {
      throw new HttpException('Group not found', 404);
    }
    return group;
  }

  async;

  async update(
    idAdmin: string,
    idGroup: string,
    updateGroupDto: UpdateGroupDto,
  ): Promise<IGroup> {
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

  async updateMembers(
    idAdmin: string,
    idGroup: string,
    updateMemberGroupDto: UpdateMemberGroupDto,
  ): Promise<IGroup> {
    await this.checkPermission(idAdmin, idGroup);
    //? Check user in list members have in database
    await this.checkUserInListIsExist(
      updateMemberGroupDto.members.map((member) => member.user),
    );

    const listUser = updateMemberGroupDto.members.map((member) => ({
      role: member.role,
      user: new ObjectId(member.user),
    }));
    //? Check user is edit members have in list members
    if (
      updateMemberGroupDto.members.filter((member) => member.user === idAdmin)
        .length === 0
    ) {
      listUser.push({
        role: ERoleGroup.ADMIN,
        user: new ObjectId(idAdmin),
      });
    }
    const res = await this.model
      .findByIdAndUpdate(
        idGroup,
        {
          members: listUser,
        },
        { new: true },
      )
      .exec();
    return res;
  }

  async addOneMemberToMemberRequest(
    idUserRequest: string,
    idUser: string,
    idGroup: string,
  ) {
    const group = await this.model.findById(idGroup).exec();
    const IsExistUserInMemberRequest = group.membersRequest.find(
      (member) => member.user.toString() === idUser,
    );
    const IsExistUserInMember = group.members.find(
      (member) => member.user.toString() === idUser,
    );
    if (IsExistUserInMemberRequest || IsExistUserInMember) {
      throw new HttpException(
        'User is exist in list members request or user is a member',
        400,
      );
    }
    await this.checkUserInListIsExist([idUser]);
    await this.model.findByIdAndUpdate(idGroup, {
      $push: {
        membersRequest: {
          user: new ObjectId(idUser),
          userAddRequest: new ObjectId(idUserRequest),
        },
      },
    });
  }

  async addMemberRequestToMembers(
    idAdmin: string,
    idGroup: string,
    listUser: IGroupMemberUpdate[],
  ) {
    await this.checkPermission(idAdmin, idGroup);
    //? Check user in list members have in database
    await this.checkUserInListIsExist(listUser.map((user) => user.user));
    const newListUserPush = listUser.map((user) => ({
      role: user.role,
      user: new ObjectId(user.user),
    }));
    const group = await this.model
      .findByIdAndUpdate(
        idGroup,
        {
          $push: {
            members: { $each: newListUserPush },
          },
          $pull: {
            membersRequest: {
              user: { $in: listUser.map((user) => new ObjectId(user.user)) },
            },
          },
        },
        {
          new: true,
        },
      )
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
      });
    return group;
  }

  async deleteMemberRequest(
    idAdmin: string,
    idGroup: string,
    listIdUser: string[],
  ) {
    await this.checkPermission(idAdmin, idGroup);
    await this.model.findByIdAndUpdate(idGroup, {
      $pull: {
        membersRequest: {
          user: { $in: listIdUser.map((id) => new ObjectId(id)) },
        },
      },
    });
  }
  ///
  async deleteGroup(idAdmin: string, idGroup: string) {
    await this.checkPermission(idAdmin, idGroup);
    await this.model.findByIdAndUpdate(idGroup, {
      isDeleted: true,
    });
  }

  async checkPermission(idUser: string, idGroup: string) {
    const group = await this.model.findById(idGroup).populate({
      path: 'members',
      populate: {
        path: 'user',
        model: 'User',
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

  async isAdmin(idUser: string, idGroup: string): Promise<boolean> {
    const group = await this.model.findById(idGroup).populate({
      path: 'members',
      populate: {
        path: 'user',
        model: 'User',
      },
    });
    if (!group) throw new HttpException('Group not found', 404);
    const haveAdmin = group.members.find(
      (member) =>
        member.user?._id.toString() === idUser &&
        member.role === ERoleGroup.ADMIN,
    );
    return !!haveAdmin;
  }

  async checkUserInListIsExist(listUser: string[]) {
    await Promise.all(
      listUser.map(async (id) => {
        return this.UserService.findById(id);
      }),
    );
  }

  async test() {
    console.log('test');
  }
}
