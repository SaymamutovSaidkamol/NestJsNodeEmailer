import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Req,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { RegisterDto, LoginDto, VerifyDto } from './dto/create-user.dto';
import { AuthGuard } from 'src/auth/auth.guard';
import { Request, RequestHandler } from 'express';
import { Roles } from 'src/decorators/role.decorator';
import { Role } from 'src/Roles/role.enum';
import { RoleGuard } from 'src/auth/role.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('/register')
  RegisterUser(@Body() data: RegisterDto) {
    return this.usersService.register(data);
  }

  @Post('/login')
  LoginUser(@Body() data: LoginDto) {
    return this.usersService.login(data);
  }

  @UseGuards(AuthGuard)
  @Get('/getMe')
  GetMe(@Req() req: Request) {
    return this.usersService.getMe(req);
  }


  
  @Post("/verify")
  Verify(@Body() data: VerifyDto){
    return this.usersService.verify(data)
  }

  @Roles(Role.ADMIN)
  @UseGuards(AuthGuard, RoleGuard)
  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  @Roles(Role.ADMIN)
  @UseGuards(AuthGuard, RoleGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @UseGuards(AuthGuard)
  @Delete(':id')
  remove(@Param('id') id: string, @Req() req: Request) {
    return this.usersService.remove(id, req);
  }

  @UseGuards(AuthGuard)
  @Delete('session/:id')
  deleteSession(@Param('id') id:string, @Req() req: Request){
    return this.usersService.delSession(id, req)
  }
}
