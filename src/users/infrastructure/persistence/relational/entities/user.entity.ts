import {
  Column,
  AfterLoad,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  JoinColumn,
  OneToOne,
  OneToMany,
} from 'typeorm';
import { FileEntity } from '../../../../../files/infrastructure/persistence/relational/entities/file.entity';

import { AuthProvidersEnum } from '../../../../../auth/auth-providers.enum';
import { EntityRelationalHelper } from '../../../../../utils/relational-entity-helper';

// We use class-transformer in ORM entity and domain entity.
// We duplicate these rules because you can choose not to use adapters
// in your project and return an ORM entity directly in response.
import { Exclude, Expose } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { StatusEnum } from '../../../../../statuses/statuses.enum';
import { RoleEnum } from '../../../../../roles/roles.enum';
import { TransactionEntity } from './transactions.entity';
import { CardEntity } from './card.entity';
import { WalletEntity } from './wallet.entity';
import { KycUpdates } from '../../../../kyc/kyc.enum';
import { EmploymentDetailsEntity } from './employmentDetails.entity';
import { BankDetailsEntity } from './bankDetails.entity';
import { NoxtOfKinEntity } from './noxtOfKin.entity';
import { TaxDetailsEntity } from './taxDetails.entity';
import { AutoMap } from '@automapper/classes';

@Entity({
  name: 'user',
})
export class UserEntity extends EntityRelationalHelper {
  @AutoMap()
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id: number;

  @AutoMap()
  @ApiProperty({ type: String, example: 'john.doe@example.com' })
  @Column({ type: String, unique: true, nullable: true })
  @Expose({ groups: ['me'] })
  email: string;

  @ApiProperty({ type: String, example: '@56newPass' })
  @Column({ nullable: true })
  @Exclude({ toPlainOnly: true })
  password?: string;

  @Exclude({ toPlainOnly: true })
  public previousPassword?: string;

  @AfterLoad()
  public loadPreviousPassword(): void {
    this.previousPassword = this.password;
  }

  @AutoMap()
  @ApiProperty({ enum: AuthProvidersEnum, example: 'email' })
  @Column({ default: AuthProvidersEnum.email })
  @Expose({ groups: ['me'] })
  provider: AuthProvidersEnum;

  @AutoMap()
  @ApiProperty({ type: String, example: 'miss, ms, mr, mrs' })
  @Index()
  @Column({ type: String, nullable: true })
  title: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'Sam' })
  @Index()
  @Column({ type: String, nullable: true })
  middleName: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'John' })
  @Index()
  @Column({ type: String, nullable: true })
  firstName: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'Doe' })
  @Index()
  @Column({ type: String, nullable: true })
  lastName: string;

  @AutoMap()
  @ApiProperty({ type: String, example: '1997/03/01' })
  @Index()
  @Column({ type: String, nullable: true })
  DOB: string;

  @AutoMap()
  @ApiProperty({ type: Number })
  @Index()
  @Column({ type: Number, nullable: true })
  age: number;

  @AutoMap()
  @ApiProperty({ type: String, example: 'male, female' })
  @Index()
  @Column({ type: String, nullable: true })
  gender: string;

  @AutoMap()
  @ApiProperty({ type: String, example: '45 abc street' })
  @Index()
  @Column({ type: String, nullable: true })
  address: string;

  @AutoMap()
  @ApiProperty({ type: String, example: '+234901230005' })
  @Index()
  @Column({ type: String, nullable: true })
  phoneNumber: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'kaduna' })
  @Index()
  @Column({ type: String, nullable: true })
  stateOfResidence: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'Nigeria' })
  @Index()
  @Column({ type: String, nullable: true })
  countryOfResidence: string;

  @ApiProperty({ type: () => FileEntity })
  @OneToOne(() => FileEntity, { eager: true })
  @JoinColumn()
  photo?: FileEntity | null;

  @AutoMap()
  @ApiProperty({ enum: RoleEnum })
  @Column({ type: 'enum', enum: RoleEnum, nullable: true })
  role: RoleEnum;

  @AutoMap()
  @ApiProperty({ enum: StatusEnum })
  @Column({ type: 'enum', enum: StatusEnum, nullable: true })
  status?: StatusEnum;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  PEP: boolean;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  PEPisdone: boolean;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  employmentStatus: string;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  employmentStatusIsdone: boolean;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  bankName: string;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  accountNumber: string;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  bankdetaislprovidedIsdone: boolean;

  @AutoMap()
  @ApiProperty({ type: Boolean })
  @Index()
  @Column({ type: 'boolean', nullable: true, default: false })
  bankVerified: boolean;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  taxLocation: string;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  taxIdentityNumber: string;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  taxdetailsprovidedIsdone: boolean;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  companyName: string;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  jobTitle: string;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  companyEmail: string;

  @AutoMap()
  @ApiProperty({ type: String, example: '+234901230005' })
  @Index()
  @Column({ type: String, nullable: true })
  companyPhone: string;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  incomeBand: string;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  investmentSource: string;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  otherInvestmentSource: string;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  employmentdetailsProvidedIsdone: boolean;

  @AutoMap()
  @ApiProperty({ type: String, example: 'judy' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinMiddlename: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'rose' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinFirstname: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'jack' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinLastname: string;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinGender: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'kin@example1.com' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinEmail: string;

  @AutoMap()
  @ApiProperty({ type: String, example: '+234901230005' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfKinPhone: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'parent' })
  @Index()
  @Column({ type: String, nullable: true })
  nextOfkinRelationship: string;

  @AutoMap()
  @ApiProperty({ type: String, example: 'in-law' })
  @Index()
  @Column({ type: String, nullable: true })
  otherNextOfKinRelationship: string;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  nextofkinDetailsprovidedIsdone: boolean;

  @AutoMap()
  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  addressProofPath: string;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  addressProofProvidedIsdone: boolean;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  governmentIdVerifiedIsdone: boolean;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  smartPhotographyIsdone: boolean;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  signatureUploadedIsdone: boolean;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', nullable: true })
  registerAndVerifiedIsdone: boolean;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column('jsonb', { nullable: false, default: '{}' })
  kycCompletionStatus: { [key in KycUpdates]: boolean };

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  zanibarAccountCreated: boolean;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  isVerified: boolean;

  @AutoMap()
  @ApiProperty()
  @Index()
  @Column({ nullable: true })
  signatureImagePath: string;

  @AutoMap()
  @ApiProperty()
  @Column({ type: 'timestamp', nullable: true })
  createdAt: Date;

  @AutoMap()
  @ApiProperty()
  @Column({ type: 'timestamp', nullable: true })
  updatedAt: Date;

  @AutoMap()
  @ApiProperty()
  @Column({ type: 'timestamp', nullable: true })
  deletedAt: Date;

  @ApiProperty({ type: () => TransactionEntity })
  @OneToMany(() => TransactionEntity, (transaction) => transaction.user)
  my_transactions: TransactionEntity[];

  @ApiProperty({ type: () => CardEntity })
  @OneToMany(() => CardEntity, (cards) => cards.user)
  my_cards: CardEntity[];

  @OneToMany(() => WalletEntity, (wallet) => wallet.owner)
  my_wallet: WalletEntity;

  @AutoMap()
  @ApiProperty()
  @Column({ nullable: true })
  resetPasswordHash: string;

  @AutoMap()
  @ApiProperty()
  @Column({ type: 'timestamp', nullable: true })
  resetPasswordExpires: Date;

  @OneToOne(() => EmploymentDetailsEntity)
  @JoinColumn() // This side owns the foreign key
  employmentDetails: EmploymentDetailsEntity;

  @OneToOne(() => BankDetailsEntity)
  @JoinColumn() // This side owns the foreign key
  bankDetails: BankDetailsEntity;

  @OneToOne(() => NoxtOfKinEntity)
  @JoinColumn() // This side owns the foreign key
  nextOfKins: NoxtOfKinEntity;

  @OneToOne(() => TaxDetailsEntity)
  @JoinColumn() // This side owns the foreign key
  taxDetails: TaxDetailsEntity;
}

// adelowo ajibola

// harmtechdevadmin
// TestDb@1234
// adelowo ajibola

// database name = tempdev
