import { ApiProperty } from '@nestjs/swagger';
import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';
import { EntityRelationalHelper } from '../../../../../utils/relational-entity-helper';

@Entity({
  name: 'employmentDetails',
})
export class EmploymentDetailsEntity extends EntityRelationalHelper {
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ type: Number })
  @Index()
  @Column({ type: Number })
  userId: number;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  companyName: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  jobTitle: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  companyEmail: string;

  @ApiProperty({ type: String, example: '+234901230005' })
  @Index()
  @Column({ type: String, nullable: true })
  companyPhone: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  incomeBand: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  investmentSource: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  otherInvestmentSource: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  employmentStatus: string;
}
