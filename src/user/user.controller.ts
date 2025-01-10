import { Body, Controller, Get, Patch, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { AtGuard } from '../common/guard';
import { GetUser } from '../common/decorator';
import { UserService } from './user.service';
import { EditUserDto } from './dto';

@UseGuards(AtGuard)
@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Get('me')
  getMe(@GetUser() user: User) {
    return user;
  }

  @Patch()
  editUser(@GetUser('id') userId: number, @Body() dto: EditUserDto) {
    return this.userService.editUser(userId, dto);
  }
}
