import { Module } from '@nestjs/common';

import { UsersController } from './users.controller';

import { UserService } from './users.service';
//import { RelationalUserPersistenceModule } from './infrastructure/persistence/relational/relational-persistence.module';
import { FilesModule } from '../files/files.module';
import { NotificationsService } from '../notifications/notifications.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from './infrastructure/persistence/relational/entities/user.entity';
import { AuthOtpEntity } from './infrastructure/persistence/relational/entities/authOtp.entity';
import { ZanzibarService } from '../utils/services/zanibar.service';
import { SmileService } from '../utils/services/smileID.service';
import { NotificationsEntity } from './infrastructure/persistence/relational/entities/notifications.entity';

//const infrastructurePersistenceModule = RelationalUserPersistenceModule;

@Module({
  imports: [ FilesModule,TypeOrmModule.forFeature([UserEntity,AuthOtpEntity,NotificationsEntity])],
  controllers: [UsersController],
  providers: [UserService,NotificationsService,ZanzibarService,SmileService],
  exports: [UserService],
})
export class UsersModule {}
