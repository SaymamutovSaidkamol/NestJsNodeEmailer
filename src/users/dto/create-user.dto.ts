import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { IsString } from 'class-validator';

export class RegisterDto {
  @ApiProperty({ example: 'Saidkamol' })
  @IsString()
  fullName: string;

  @ApiProperty({ example: 'cryptouchun06@gmail.com' })
  @IsString()
  email: string;

  @ApiProperty({ example: '1234' })
  @IsString()
  password: string;

  @ApiProperty({ example: 'Saidkamol.jpg' })
  @IsString()
  img: string;

  @ApiProperty({ example: ['USER', 'ADMIN'] })
  @IsString()
  role: Role;
}

export class LoginDto {
  @ApiProperty({ example: 'cryptouchun06@gmail.com' })
  @IsString()
  email: string;

  @ApiProperty({ example: '1234' })
  @IsString()
  password: string;

  @ApiProperty({ example: '1.2.1.1.0' })
  @IsString()
  IP: string;
}

export class VerifyDto {
  @ApiProperty({ example: 'cryptouchun06@gmail.com' })
  @IsString()
  email: string;

  @ApiProperty({ example: '123456' })
  @IsString()
  otp: string;
}
