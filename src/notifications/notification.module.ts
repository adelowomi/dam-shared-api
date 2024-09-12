// notifications.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { NotificationsService } from './notifications.service';
import { NotificationsEntity } from '../users/infrastructure/persistence/relational/entities/notifications.entity';

@Module({
  imports: [TypeOrmModule.forFeature([NotificationsEntity])],
  providers: [NotificationsService],
  exports: [NotificationsService],  // Export it so other modules can use it
})
export class NotificationsModule {}
