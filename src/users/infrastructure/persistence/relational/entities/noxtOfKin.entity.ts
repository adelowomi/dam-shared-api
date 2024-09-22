import { ApiProperty } from '@nestjs/swagger';
import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';
import { EntityRelationalHelper } from '../../../../../utils/relational-entity-helper';

@Entity({
  name: 'nextOfKin',
})
export class NoxtOfKinEntity extends EntityRelationalHelper {
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id;

  @ApiProperty({ type: Number })
  @Column({ type: Number })
  @Index()
  userId;

  @ApiProperty({ type: String, example: 'judy' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinMiddlename: string;

  @ApiProperty({ type: String, example: 'rose' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinFirstname: string;

  @ApiProperty({ type: String, example: 'jack' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinLastname: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinGender: string;

  @ApiProperty({ type: String, example: 'kin@example1.com' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinEmail: string;

  @ApiProperty({ type: String, example: '+234901230005' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinPhone: string;

  @ApiProperty({ type: String, example: 'parent' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfkinRelationship: string;

  @ApiProperty({ type: String, example: 'in-law' })
  @Index()
  @Column({ type: String, nullable: true })
  otherNextOfKinRelationship: string;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  nextofkinDetailsprovidedIsdone: boolean;
}
