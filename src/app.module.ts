import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { FilesModule } from './files/files.module';
import { AuthModule } from './auth/auth.module';
import databaseConfig from './database/config/database.config';
import authConfig from './auth/config/auth.config';
import appConfig from './config/app.config';

import fileConfig from './files/config/file.config';
import path from 'path';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { I18nModule } from 'nestjs-i18n/dist/i18n.module';
import { HeaderResolver } from 'nestjs-i18n';
import { TypeOrmConfigService } from './database/typeorm-config.service';

import { HomeModule } from './home/home.module';
import { DataSource, DataSourceOptions } from 'typeorm';
import { AllConfigType } from './config/config.type';
import { SessionModule } from './session/session.module';
import { MailerModule } from '@nestjs-modules/mailer';
import { NotificationsModule } from './notifications/notification.module';
import { PaymentGatewayModule } from './payment/payment.module';
import { FetchModule } from 'nestjs-fetch';
import { CustomFetchModule } from './utils/modules/customFetch.module.';
import { AutomapperModule } from '@automapper/nestjs';
import { classes } from '@automapper/classes';
import { UtilitiesModule } from './utilities/utilities.module';

const infrastructureDatabaseModule = TypeOrmModule.forRootAsync({
  useClass: TypeOrmConfigService,
  dataSourceFactory: async (options: DataSourceOptions) => {
    return new DataSource(options).initialize();
  },
});

@Module({
  imports: [
    AutomapperModule.forRoot({
      strategyInitializer: classes(),
    }),
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, authConfig, appConfig, fileConfig],
      envFilePath: ['.env'],
    }),
    infrastructureDatabaseModule,
    // I18nModule.forRootAsync({
    //   useFactory: (configService: ConfigService<AllConfigType>) => ({
    //     fallbackLanguage: configService.getOrThrow('app.fallbackLanguage', {
    //       infer: true,
    //     }),
    //     loaderOptions: { path: path.join(__dirname, '/i18n/'), watch: true },
    //   }),
    //   resolvers: [
    //     {
    //       use: HeaderResolver,
    //       useFactory: (configService: ConfigService<AllConfigType>) => {
    //         return [
    //           configService.get('app.headerLanguage', {
    //             infer: true,
    //           }),
    //         ];
    //       },
    //       inject: [ConfigService],
    //     },
    //   ],
    //   imports: [ConfigModule],
    //   inject: [ConfigService],
    // }),
    UsersModule,
    FilesModule,
    AuthModule,
    SessionModule,
    NotificationsModule,
    PaymentGatewayModule,
    MailerModule.forRoot({
      transport: {
        service: 'gmail',
        host: 'smtp.gmail.com',
        port: 587,
        secure: true,
        auth: {
          user: process.env.AUTH_EMAIL,
          pass: process.env.AUTH_PASS,
        },
      },
    }),
    FetchModule,
    CustomFetchModule,
    HomeModule,
    UtilitiesModule,
  ],
})
export class AppModule {}
