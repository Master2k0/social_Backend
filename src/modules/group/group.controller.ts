import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

import { ResponseMessage } from '@/common/decorator/response.decorator';
import { AccessTokenGuard } from '@/modules/auth/guards/accessToken.guard';
import { ITokenRequest } from '@/types/tokenRequest';

import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';
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
    return await this.groupService.create(req.user.id, createGroupDto);
  }

  @Post('update/:id')
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

  @Get()
  findAll() {
    return this.groupService.findAll();
  }

  @Get(':slug')
  findOne(@Param('slug') slug: string) {
    return this.groupService.findBySlug(slug);
  }

  // @Patch(':id')
  // @UseGuards(AccessTokenGuard)
  // @ApiBearerAuth('JWT-auth')
  // update(@Param('id') id: string, @Body() updateGroupDto: UpdateGroupDto) {
  //   return this.groupService.update(+id, updateGroupDto);
  // }

  // @Delete(':id')
  // @UseGuards(AccessTokenGuard)
  // @ApiBearerAuth('JWT-auth')
  // remove(@Param('id') id: string) {
  //   return this.groupService.remove(+id);
  // }
}
