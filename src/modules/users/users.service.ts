import {
  HttpException,
  HttpStatus,
  Injectable,
  UseFilters,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import { HttpExceptionFilter } from '@/common/exception/httpException.filter';
import { hashPassword } from '@/utils/hashPassword';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User, UserDocument } from './schema/users.schema';

@Injectable()
@UseFilters(new HttpExceptionFilter())
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly model: Model<UserDocument>,
  ) {}
  async create(createUserDto: CreateUserDto): Promise<UserDocument> {
    const newPassword = await hashPassword(createUserDto.password);
    const user = await this.model.create({
      ...createUserDto,
      password: newPassword,
    });
    return user;
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.model.findById(id).exec();
    if (!user) {
      throw new HttpException(
        {
          status: HttpStatus.NOT_FOUND,
          error: 'User not found',
        },
        HttpStatus.NOT_FOUND,
      );
    }
    const res = await this.model
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .exec();

    return res;
  }

  async delete(id: string): Promise<User> {
    try {
      return await this.model.findByIdAndDelete(id).exec();
    } catch (error) {
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: error.message,
        },
        HttpStatus.BAD_REQUEST,
        { cause: error },
      );
    }
  }

  findAll() {
    return `This action returns all users`;
  }

  async findByUserName(userName: string): Promise<User> {
    const user = await this.model.findOne({ userName: userName }).exec();
    if (!user)
      throw new HttpException(
        {
          status: HttpStatus.NOT_FOUND,
          error: 'User not found',
        },
        HttpStatus.NOT_FOUND,
      );

    return user;
  }

  async findById(id: string) {
    const user = await this.model.findById(id);
    if (!user) {
      throw new HttpException(
        {
          status: HttpStatus.NOT_FOUND,
          error: 'User not found',
        },
        HttpStatus.NOT_FOUND,
      );
    }
    return user;
  }
}
