import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { EntityRelationalHelper } from '../../../../../utils/relational-entity-helper';
import { ApiProperty } from '@nestjs/swagger';

@Entity({ name: 'smileLinks' })
export class SmileLinksEntity extends EntityRelationalHelper {
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ type: String })
  @Column({ type: String, unique: true, nullable: true })
  link: string;

  @ApiProperty({ type: String })
  @Column({ type: String, unique: true, nullable: true })
  link_id: string;

  @ApiProperty({ type: String })
  @Column({ unique: false })
  email: string;

  @ApiProperty({ type: String })
  @Column({ unique: true })
  ref_id: string;

  @ApiProperty({ type: Number })
  @Column({ unique: false })
  user_id: number;

  @ApiProperty()
  @CreateDateColumn()
  created_at: Date;
}
