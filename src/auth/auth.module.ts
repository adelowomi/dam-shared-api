import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { AnonymousStrategy } from './strategies/anonymous.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';

import { SessionModule } from '../session/session.module';
import { UsersModule } from '../users/users.module';
import { NotificationsService } from '../notifications/notifications.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { NotificationsModule } from '../notifications/notification.module';
import { NotificationsEntity } from '../users/infrastructure/persistence/relational/entities/notifications.entity';
import { UserEntity } from '../users/infrastructure/persistence/relational/entities/user.entity';
import { AuthOtpEntity } from '../users/infrastructure/persistence/relational/entities/authOtp.entity';
import { Mailer } from '../mail/mail.service';
import { SessionService } from '../session/session.service';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../users/users.service';

@Module({
  imports: [
    //UsersModule,
    SessionModule,
    PassportModule,
    JwtModule.register({}),
    TypeOrmModule.forFeature([UserEntity,NotificationsEntity,AuthOtpEntity])
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, JwtRefreshStrategy, UserService,AnonymousStrategy,NotificationsService,Mailer,SessionService,JwtService],
  exports: [AuthService],
})
export class AuthModule {}
