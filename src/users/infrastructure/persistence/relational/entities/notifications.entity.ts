import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { EntityRelationalHelper } from '../../../../../utils/relational-entity-helper';
import { ApiProperty } from '@nestjs/swagger';

@Entity('notifications')
export class NotificationsEntity extends EntityRelationalHelper {
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({})
  @CreateDateColumn()
  date: Date;

  @ApiProperty({ type: Number })
  @Column({ nullable: false })
  account: number;

  @ApiProperty({ type: String })
  @Column({ nullable: false })
  message: string;

  @ApiProperty({ type: String })
  @Column({ nullable: false })
  subject: string;

  @ApiProperty({ type: Boolean })
  @Column({ nullable: true, type: 'boolean', default: false })
  isRead: boolean;
}
