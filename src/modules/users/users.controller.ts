import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

import { ResponseMessage } from '@/common/decorator/response.decorator';
import { AccessTokenGuard } from '@/modules/auth/guards/accessToken.guard';
import { ResponseUser } from '@/modules/users/dto/response-user.dto';
import { ITokenRequest } from '@/types/tokenRequest';

import { UpdateUserDto } from './dto/update-user.dto';
import { UsersService } from './users.service';

@ApiTags('user')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('User data')
  async userMe(@Req() req: ITokenRequest) {
    const user = await this.usersService.findById(req.user.id);
    return user.toDto(ResponseUser);
  }

  @Get(':id')
  // @UseGuards(AccessTokenGuard)
  @HttpCode(201)
  @ResponseMessage('User data')
  findOne(@Param('id') id: string) {
    return this.usersService.findById(id);
  }

  @Patch('update')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(201)
  @ResponseMessage('Update user successfully')
  update(@Req() request: ITokenRequest, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(request.user.id, updateUserDto);
  }

  @Delete(':id')
  @UseGuards(AccessTokenGuard)
  @HttpCode(201)
  @ResponseMessage('Delete user successfully')
  delete(@Param('id') id: string) {
    return this.usersService.delete(id);
  }
}
