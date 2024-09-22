import { ApiProperty } from '@nestjs/swagger';
import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';
import { EntityRelationalHelper } from '../../../../../utils/relational-entity-helper';

@Entity({
  name: 'bankDetails',
})
export class BankDetailsEntity extends EntityRelationalHelper {
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ type: Number })
  @Column({ type: Number })
  @Index()
  userId: number;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  bankName: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  accountNumber: string;

  @ApiProperty({ type: Boolean })
  @Index()
  @Column({ type: 'boolean', nullable: true, default: false })
  bankVerified: boolean;
}
