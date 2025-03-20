import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class RefreshGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  canActivate(context: ExecutionContext): boolean {
    let request: Request = context.switchToHttp().getRequest();

    let { token } = request.body;

    if (!token) {
        console.log(token);
        
      throw new BadRequestException('Token Not Found');
    }

    try {
      let data = this.jwtService.verify(token, {secret: "refresh_key"});

      request['user'] = data;
      return true;
    } catch (error) {
      throw new BadRequestException();
    }
  }
}
