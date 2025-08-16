import { Body, Controller, Get, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../auth/role/roles.guard';
import { Roles } from '../auth/role/roles.decorator';
import { Role } from '../auth/role/roles.enum';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(Role.Student)
  @Get()
  getAllUser(): object {
    const user = this.usersService.getAllUsers();
    return user;
  }
}
