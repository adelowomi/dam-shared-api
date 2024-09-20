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
import { KycService } from './kyc/user.kyc.service';
import { KycController } from './kyc/user.kyc.controller';
import { FilesS3Service } from '../files/infrastructure/uploader/s3/files.service';
import { WalletEntity } from './infrastructure/persistence/relational/entities/wallet.entity';
import { PaymentGatewayService } from '../payment/payment.service';
import { WalletService } from './wallet/wallet.service';
import { WalletController } from './wallet/wallet.controller';
import { Mailer } from '../mail/mail.service';
import { FilesS3PresignedService } from '../files/infrastructure/uploader/s3-presigned/files.service';
import { ResponseService } from '../utils/services/response.service';
import { AnonymousStrategy } from '../auth/strategies/anonymous.strategy';
import { PassportModule } from '@nestjs/passport';
import { SmileLinksEntity } from './infrastructure/persistence/relational/entities/smilelinks.entity';
import { FetchModule } from 'nestjs-fetch';

//const infrastructurePersistenceModule = RelationalUserPersistenceModule;

@Module({
  imports: [
    FilesModule,
    PassportModule,
    TypeOrmModule.forFeature([
      UserEntity,
      AuthOtpEntity,
      NotificationsEntity,
      WalletEntity,
      SmileLinksEntity,
    ]),
    FetchModule,
  ],
  controllers: [UsersController, KycController, WalletController],
  providers: [
    UserService,
    NotificationsService,
    ZanzibarService,
    SmileService,
    KycService,
    FilesS3Service,
    FilesS3PresignedService,
    PaymentGatewayService,
    WalletService,
    Mailer,
    ResponseService,
    AnonymousStrategy,
  ],
  exports: [UserService],
})
export class UsersModule {}
