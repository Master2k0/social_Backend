import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpException,
  Param,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

import { AllowAccessWithoutToken } from '@/common/decorator/getTokenWithoutGuards.decorator';
import { ResponseMessage } from '@/common/decorator/response.decorator';
import { AccessTokenGuard } from '@/modules/auth/guards/accessToken.guard';
import { AddMemberRequestToGroupDto } from '@/modules/group/dto/add-member-group.dto';
import { RemoveMemberFromGroupDto } from '@/modules/group/dto/remove-member-from-memberRequest.dto';
import { ITokenRequest } from '@/types/tokenRequest';

import { CreateGroupDto } from './dto/create-group.dto';
import { ResponseGroup } from './dto/response-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';
import { UpdateMemberGroupDto } from './dto/updateMember-group.dto';
import { GroupService } from './group.service';

@ApiTags('group')
@Controller('group')
export class GroupController {
  constructor(private readonly groupService: GroupService) {}

  @Post('create')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Create group successfully')
  async create(
    @Req() req: ITokenRequest,
    @Body() createGroupDto: CreateGroupDto,
  ) {
    // console.log(req.user);
    return await this.groupService.create(req.user.id, createGroupDto);
  }

  @Patch('update/:id')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Update group successfully')
  async update(
    @Req() req: ITokenRequest,
    @Body() update: UpdateGroupDto,
    @Param('id') id: string,
  ) {
    return await this.groupService.update(req.user.id, id, update);
  }

  @Patch('update/members/:id')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Update members group successfully')
  async updateMembers(
    @Req() req: ITokenRequest,
    @Body() update: UpdateMemberGroupDto,
    @Param('id') id: string,
  ) {
    const isAdmin = await this.groupService.isAdmin(req.user.id, id);
    if (!isAdmin) throw new HttpException('Not permission', 403);
    return await this.groupService.updateMembers(req.user.id, id, update);
  }

  @Patch('update/addMemberRequest/:id')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Add user to list user request successfully')
  async addUserRequest(
    @Req() req: ITokenRequest,
    @Param('id') id: string,
    @Body() body: AddMemberRequestToGroupDto,
  ) {
    await this.groupService.addOneMemberToMemberRequest(
      req.user.id,
      body.idUser,
      id,
    );
  }

  @Patch('update/addMemberRequestToMember/:id')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Add user to list user request successfully')
  async addUserRequestToMember(
    @Req() req: ITokenRequest,
    @Param('id') id: string,
    @Body() body: UpdateMemberGroupDto,
  ) {
    return await this.groupService.addMemberRequestToMembers(
      req.user.id,
      id,
      body.members,
    );
  }

  @Get(':slug')
  @UseGuards(AccessTokenGuard)
  @AllowAccessWithoutToken()
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Update members group successfully')
  async findOne(@Req() req: ITokenRequest, @Param('slug') slug: string) {
    const group = await this.groupService.findBySlug(slug);
    const idUserRequest = req?.user?.id || '';
    const isAdmin = await this.groupService.isAdmin(idUserRequest, group?._id);
    if (isAdmin) {
      return group;
    } else {
      return group.toDto(ResponseGroup);
    }
  }

  @Delete('/delete/memberRequest/:id')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Delete user request successfully')
  async deleteUserRequest(
    @Req() req: ITokenRequest,
    @Param('id') id: string,
    @Body() body: RemoveMemberFromGroupDto,
  ) {
    return await this.groupService.deleteMemberRequest(
      req.user.id,
      id,
      body.listIdUser,
    );
  }

  @Delete('/delete/:id')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Delete group successfully')
  async deleteGroup(@Req() req: ITokenRequest, @Param('id') id: string) {
    return await this.groupService.deleteGroup(req.user.id, id);
  }
}
