import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { MailModule } from 'src/mail/mail.module';

@Module({
  controllers: [UsersController],
  providers: [UsersService],
  imports: [
    MailModule,
    JwtModule.register({
      global: true,
      secret: 'access_key',
      signOptions: { expiresIn: '20s' },
    }),
  ],
  exports: [JwtModule],
})
export class UsersModule {}
