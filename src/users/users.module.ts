import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { JwtModule } from '@nestjs/jwt';
import { MailModule } from 'src/mail/mail.module';

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: 'salom',
      signOptions: { expiresIn: '15m' },
    }),
    MailModule
  ],
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
