import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from '../common/types';
import { JwtGuard } from '../common/guard';
import { GetUser } from '../common/decorator';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signIn(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signIn(dto);
  }

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  signUp(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signUp(dto);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Get('refresh')
  @HttpCode(HttpStatus.OK)
  refeshToken(@Req() req: Request) {
    const user = req.user;
    return this.authService.refreshToken(user['sub'], user['refreshToken']);
  }

  @UseGuards(JwtGuard)
  @Get('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetUser() user: User) {
    this.authService.logout(user.id);
  }
}
