import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { RegisterDto, LoginDto, VerifyDto } from './dto/create-user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { MailService } from 'src/mail/mail.service';
import { totp } from 'otplib';

totp.options = { step: 120 };

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private mailer: MailService,
  ) {}
  async register(data: RegisterDto) {
    let checkUser = await this.prisma.users.findFirst({
      where: { fullName: data.fullName },
    });

    if (checkUser) {
      let otp = totp.generate('secret' + data.email);

      let sendOtp = await this.mailer.sendMail(
        data.email,
        'New Otp',
        `new Otp:  ${otp}`,
      );
      return { message: 'New OTP', otp };
    }
    let hashPass = bcrypt.hashSync(data.password, 7);

    data.password = hashPass;

    let newUser = await this.prisma.users.createMany({ data });
    let otp = totp.generate('secret' + data.email);

    let sendOtp = await this.mailer.sendMail(
      data.email,
      'New Otp',
      `new Otp:  ${otp}`,
    );

    return {
      message: 'Register Successfully, OTP sent, please activate your account',
      otp,
    };
  }

  async login(data: LoginDto) {
    let checkUser = await this.prisma.users.findFirst({
      where: { email: data.email },
    });

    if (!checkUser) {
      throw new NotFoundException('User Not Found');
    }

    let chechPass = bcrypt.compareSync(data.password, checkUser.password);

    if (!chechPass) {
      throw new NotFoundException('Wrong Password');
    }

    let token = this.generateAccessToken({
      id: checkUser.id,
      name: checkUser.fullName,
      Ip: data.IP,
      role: checkUser.role,
      status: checkUser.status,
    });

    let refreshToken = this.generateRefreshToken({
      id: checkUser.id,
      name: checkUser.fullName,
      Ip: data.IP,
      role: checkUser.role,
      status: checkUser.status,
    });

    let IpCheck = await this.prisma.iP.findFirst({
      where: { ID_Adress: data.IP, userId: checkUser.id },
    });

    if (!IpCheck) {
      console.log(
        `Yangi IP-manzil qo‘shilmoqda: ${data.IP} - User: ${checkUser.id}`,
      );

      console.log(checkUser.status);

      if (checkUser.status !== 'ACTIVE') {
        throw new BadRequestException('Plase ACTIVATE yout acount');
      }

      await this.prisma.iP.create({
        data: {
          ID_Adress: data.IP,
          userId: checkUser.id,
        },
      });
    }

    let verifyToken = this.jwtService.verify(token);

    return {
      acces_token: token,
      refresh_token: refreshToken,
      OTP: verifyToken,
    };
  }

  async getMe(req: Request) {
    let { id } = req['user'];

    let all = await this.prisma.iP.findMany({
      where: { userId: id },
      include: { user: true },
    });

    return { data: all };
  }

  async findAll() {
    let all = await this.prisma.users.findMany({
      include: { ip: true },
    });
    return { data: all };
  }

  async findOne(id: string) {
    let OneCateg = await this.prisma.users.findFirst({
      where: { id },
      include: { ip: true },
    });

    if (!OneCateg) {
      throw new NotFoundException('Users Not Found');
    }

    return { data: OneCateg };
  }

  async remove(id: string, req: Request) {
    console.log(req['user']);

    if (req['user'].id !== id || req['user'].role !== 'ADMIN') {
      throw new BadRequestException(
        'You cannot send your information to someone else.',
      );
    }

    let OneCateg = await this.prisma.users.findFirst({ where: { id } });

    if (!OneCateg) {
      throw new NotFoundException('Users Not Found');
    }

    let del = await this.prisma.users.delete({ where: { id } });

    return { data: del };
  }

  async delSession(id: string, req: Request) {
    let checkIp = await this.prisma.iP.findFirst({ where: { id } });

    if (!checkIp) {
      throw new NotFoundException('IP Not Found');
    }

    if (checkIp.userId !== req['user'].id) {
      throw new BadRequestException();
    }

    let del = await this.prisma.iP.delete({ where: { id } });

    return { del };
  }

  async verify(data: VerifyDto) {
    let secret = 'secret' + data.email;

    let checkuser = await this.prisma.users.findFirst({
      where: { email: data.email },
    });
    let verifyOtp = totp.verify({ token: data.otp, secret });

    if (!checkuser) {
      throw new NotFoundException('User Not Found');
    }
    if (!verifyOtp) {
      throw new BadRequestException('Invalid Otp');
    }

    let UpdateUser = await this.prisma.users.update({
      where: { email: data.email },
      data: { status: 'ACTIVE' },
    });

    return { message: 'Your account has been activated.' };
  }

  async refresh_token(req: Request) {
    let { id, name, Ip, role, status } = req['user'];
    console.log(req['user']);

    return {
      message: 'New Access Token',
      access_token: this.generateRefreshToken({ id, name, Ip, role, status }), // generete -> generate
    };
  }

  generateAccessToken(payload: any) {
    return this.jwtService.sign(payload, {
      secret: 'access_key',
      expiresIn: '20s', // 15 daqiqa
    });
  }
  
  generateRefreshToken(payload: any) {
    return this.jwtService.sign(payload, {
      secret: 'refresh_key',
      expiresIn: '59s', // 7 kun
    });
  }
  
}
