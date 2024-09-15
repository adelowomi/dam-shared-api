import {
  Column,
  AfterLoad,
  CreateDateColumn,
  DeleteDateColumn,
  Entity,
  Index,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
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

@Entity({
  name: 'user',
})
export class UserEntity extends EntityRelationalHelper {
  @ApiProperty({ type: Number })
  @PrimaryGeneratedColumn()
  id: number;

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

  @ApiProperty({ enum: AuthProvidersEnum, example: 'email' })
  @Column({ default: AuthProvidersEnum.email })
  @Expose({ groups: ['me'] })
  provider: AuthProvidersEnum;

  @ApiProperty({ type: String, example: 'miss, ms, mr, mrs' })
  @Index()
  @Column({ type: String, nullable: true })
  title: string;

  @ApiProperty({ type: String, example: 'Sam' })
  @Index()
  @Column({ type: String, nullable: true })
  middleName: string;

  @ApiProperty({ type: String, example: 'John' })
  @Index()
  @Column({ type: String, nullable: true })
  firstName: string;

  @ApiProperty({ type: String, example: 'Doe' })
  @Index()
  @Column({ type: String, nullable: true })
  lastName: string;

  @ApiProperty({ type: String, example: '1997/03/01' })
  @Index()
  @Column({ type: String, nullable: true })
  DOB: string;

  @ApiProperty({ type: Number })
  @Index()
  @Column({ type: Number, nullable: true })
  age: number;

  @ApiProperty({ type: String, example: 'male, female' })
  @Index()
  @Column({ type: String, nullable: true })
  gender: string;

  @ApiProperty({ type: String, example: '45 abc street' })
  @Index()
  @Column({ type: String, nullable: true })
  address: string;

  @ApiProperty({ type: String, example: '+234901230005' })
  @Index()
  @Column({ type: String, nullable: true })
  phoneNumber: string;

  @ApiProperty({ type: String, example: 'kaduna' })
  @Index()
  @Column({ type: String, nullable: true })
  stateOfResidence: string;

  @ApiProperty({ type: String, example: 'Nigeria' })
  @Index()
  @Column({ type: String, nullable: true })
  countryOfResidence: string;

  @ApiProperty({ type: () => FileEntity })
  @OneToOne(() => FileEntity, { eager: true })
  @JoinColumn()
  photo?: FileEntity | null;

  @ApiProperty({ enum: RoleEnum })
  @Column({ type: 'enum', enum: RoleEnum ,nullable:true})
  role: RoleEnum;

  @ApiProperty({ enum: StatusEnum })
  @Column({ type: 'enum', enum: StatusEnum, nullable:true })
  status?: StatusEnum;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean' ,nullable:true})
  PEP: boolean;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  employmentStatus: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  bankName: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  accountNumber: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  taxLocation: string;

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  taxIdentityNumber: string;

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

  @ApiProperty({ type: String })
  @Index()
  @Column({ type: String, nullable: true })
  addressProofPath: string;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  passportPhotographVerificationInitiated: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  PEPupdated: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'decimal',nullable:true })
  kycCompletionPercentage: number;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  zanibarAccountCreated: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  employmentDetailsProvided: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  nextOfKinDetailsProvided: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  userRegisteredAndVerified: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  bankDetailsProvided: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  addressProofProvided: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  governmentIdProvided: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  taxDetailsProvided: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  signatureUploaded: boolean;

  @ApiProperty()
  @Index()
  @Column({ type: 'boolean', default: false })
  isVerified: boolean;

  @ApiProperty()
  @Index()
  @Column({ nullable: true })
  signatureImagePath: string;

  @ApiProperty()
  @Column({ type: 'timestamp', nullable:true })
  createdAt: Date;

  @ApiProperty()
  @Column({ type: 'timestamp' , nullable:true})
  updatedAt: Date;

  @ApiProperty()
  @Column({ type: 'timestamp', nullable:true })
  deletedAt: Date;

  @ApiProperty({type:()=> TransactionEntity})
  @OneToMany(() => TransactionEntity, transaction => transaction.user)
  my_transactions: TransactionEntity[];

  @ApiProperty({type:()=> CardEntity})
  @OneToMany(() => CardEntity, cards => cards.user)
  my_cards: CardEntity[];

  @OneToMany(() => WalletEntity, wallet => wallet.owner)
  my_wallet: WalletEntity;

}

// adelowo ajibola

// harmtechdevadmin
// TestDb@1234
// adelowo ajibola

// database name = tempdev
