import { ApiProperty } from '@nestjs/swagger';
import { EntityRelationalHelper } from '../../../../../utils/relational-entity-helper';
import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

@Entity({
  name: 'taxDetails',
})
export class TaxDetailsEntity extends EntityRelationalHelper {
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id;

  @ApiProperty({ type: Number })
  @Column({ type: Number })
  @Index()
  userId;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  taxLocation: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  taxIdentityNumber: string;
}
