import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { EntityRelationalHelper } from '../../../../../utils/relational-entity-helper';
import { ApiProperty } from '@nestjs/swagger';
import { RoleEnum } from '../../../../../roles/roles.enum';

@Entity({ name: 'authOtp' })
export class AuthOtpEntity extends EntityRelationalHelper {
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ type: String })
  @Column({ type: String, unique: true, nullable: true })
  otp: string;

  @ApiProperty({ type: String })
  @Column({ unique: false })
  email: string;

  @ApiProperty({ type: String })
  @Column({ type: 'enum', enum: RoleEnum, nullable: true })
  role: RoleEnum;

  @ApiProperty({ type: Boolean })
  @Column({ type: 'boolean', default: false })
  verified: boolean;

  @ApiProperty()
  @Column({ nullable: true, type: 'timestamp' })
  expiration_time: Date;

  @ApiProperty()
  @Column({ nullable: true, type: 'timestamp' })
  resend_time: Date;

  @ApiProperty()
  @CreateDateColumn()
  created_at: Date;
}
