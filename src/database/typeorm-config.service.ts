import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions, TypeOrmOptionsFactory } from '@nestjs/typeorm';
import { UserEntity } from '../users/infrastructure/persistence/relational/entities/user.entity';
import { NotificationsEntity } from '../users/infrastructure/persistence/relational/entities/notifications.entity';
import { TransactionEntity } from '../users/infrastructure/persistence/relational/entities/transactions.entity';
import { AuthOtpEntity } from '../users/infrastructure/persistence/relational/entities/authOtp.entity';
import { WalletEntity } from '../users/infrastructure/persistence/relational/entities/wallet.entity';
import { CardEntity } from '../users/infrastructure/persistence/relational/entities/card.entity';
import { FileEntity } from '../files/infrastructure/persistence/relational/entities/file.entity';
import { SessionEntity } from '../session/infrastructure/persistence/relational/entities/session.entity';
import { SmileLinksEntity } from '../users/infrastructure/persistence/relational/entities/smilelinks.entity';
import { EmploymentDetailsEntity } from '../users/infrastructure/persistence/relational/entities/employmentDetails.entity';
import { BankDetailsEntity } from '../users/infrastructure/persistence/relational/entities/bankDetails.entity';
import { NoxtOfKinEntity } from '../users/infrastructure/persistence/relational/entities/noxtOfKin.entity';
import { TaxDetailsEntity } from '../users/infrastructure/persistence/relational/entities/taxDetails.entity';

@Injectable()
export class TypeOrmConfigService implements TypeOrmOptionsFactory {
  constructor(private configService: ConfigService) {}

  createTypeOrmOptions(): TypeOrmModuleOptions {
    return {
      type: this.configService.get('DATABASE_TYPE', { infer: true }),
      //url: this.configService.get('database.url', { infer: true }),
      host: this.configService.get('DATABASE_HOST', { infer: true }),
      port: this.configService.get('DATABASE_PORT', { infer: true }),
      username: this.configService.get('DATABASE_USERNAME', { infer: true }),
      password: this.configService.get('DATABASE_PASSWORD', { infer: true }),
      database: this.configService.get('DATABASE_NAME', { infer: true }),
      synchronize: this.configService.get('DATABASE_SYNCHRONIZE', {
        infer: true,
      }),
      dropSchema: false,
      keepConnectionAlive: true,
      logging:
        this.configService.get('app.nodeEnv', { infer: true }) !== 'production',
      entities: [
        UserEntity,
        NotificationsEntity,
        TransactionEntity,
        AuthOtpEntity,
        WalletEntity,
        CardEntity,
        FileEntity,
        SessionEntity,
        SmileLinksEntity,
        EmploymentDetailsEntity,
        BankDetailsEntity,
        NoxtOfKinEntity,
        TaxDetailsEntity,
      ],
      migrations: [__dirname + '/migrations/**/*{.ts,.js}'],
      cli: {
        entitiesDir: 'src',

        subscribersDir: 'subscriber',
      },
      extra: {
        // based on https://node-postgres.com/apis/pool
        // max connection pool size
        max: this.configService.get('database.maxConnections', { infer: true }),
        ssl: this.configService.get('database.sslEnabled', { infer: true })
          ? {
              rejectUnauthorized: this.configService.get(
                'database.rejectUnauthorized',
                { infer: true },
              ),
              ca:
                this.configService.get('database.ca', { infer: true }) ??
                undefined,
              key:
                this.configService.get('database.key', { infer: true }) ??
                undefined,
              cert:
                this.configService.get('database.cert', { infer: true }) ??
                undefined,
            }
          : undefined,
      },
    } as TypeOrmModuleOptions;
  }
}
