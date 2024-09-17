import { Exclude, Expose, Type } from 'class-transformer';
import { FileType } from '../../files/domain/file';
import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsDate,
  IsEmail,
  IsEnum,
  IsJSON,
  IsNumber,
  IsOptional,
  IsString,
} from 'class-validator';
import { StatusEnum } from '../../statuses/statuses.enum';

import { FileEntity } from '../../files/infrastructure/persistence/relational/entities/file.entity';
import { AuthProvidersEnum } from '../../auth/auth-providers.enum';
import { RoleEnum } from '../../roles/roles.enum';
import { TransactionEntity } from '../infrastructure/persistence/relational/entities/transactions.entity';
import { KycUpdates } from '../kyc/kyc.enum';

const idType = Number;
export class User {
  @ApiProperty({ type: Number })
  @IsNumber()
  id: number;

  @ApiProperty({ type: String, example: 'john.doe@example.com' })
  @Expose({ groups: ['me'] })
  @IsEmail()
  email: string;

  @Exclude({ toPlainOnly: true })
  @IsString()
  @IsOptional()
  password?: string;

  @Exclude({ toPlainOnly: true })
  previousPassword?: string;

  @ApiProperty({ type: String, example: 'email', enum: AuthProvidersEnum })
  @Expose({ groups: ['me'] })
  @IsEnum(AuthProvidersEnum)
  provider: AuthProvidersEnum;

  @ApiProperty({ type: String, example: 'mr, ms, mrs, miss' })
  @IsString()
  title: string;

  @ApiProperty({ type: String, example: 'John' })
  @IsString()
  firstName: string;

  @ApiProperty({ type: String, example: 'Doe' })
  @IsString()
  lastName: string;

  @ApiProperty({ type: String, example: 'Sam' })
  @IsString()
  @IsOptional()
  middleName?: string;

  @ApiProperty({ type: () => FileEntity })
  @Type(() => FileEntity)
  photo?: FileEntity | null;

  @ApiProperty({ type: String })
  @IsString()
  DOB: string;

  @ApiProperty({ type: Number })
  @IsNumber()
  age: number;

  @ApiProperty({ type: String })
  @IsString()
  gender: string;

  @ApiProperty({ type: String })
  @IsString()
  address: string;

  @ApiProperty({ type: String })
  @IsString()
  phoneNumber: string;

  @ApiProperty({ type: String })
  @IsString()
  stateOfResidence: string;

  @ApiProperty({ type: String })
  @IsString()
  countryOfResidence: string;

  @ApiProperty({ type: Boolean })
  @IsString()
  PEP: boolean;

  @ApiProperty({ type: String })
  @IsString()
  employmentStatus: string;

  @ApiProperty({ type: String })
  @IsString()
  bankName: string;

  @ApiProperty({ type: String })
  @IsString()
  accountNumber: string;

  @ApiProperty({ type: String })
  @IsString()
  taxLocation: string;

  @ApiProperty({ type: String })
  @IsString()
  taxIdentityNumber: string;

  @ApiProperty({ type: String })
  @IsString()
  companyName: string;

  @ApiProperty({ type: String })
  @IsString()
  jobTitle: string;

  @ApiProperty({ type: String })
  @IsString()
  @IsEmail()
  companyEmail: string;

  @ApiProperty({ type: String })
  @IsString()
  companyPhone: string;

  @ApiProperty({ type: String })
  @IsString()
  incomeBand: string;

  @ApiProperty({ type: String })
  @IsString()
  investmentSource: string;

  @ApiProperty({ type: String })
  @IsString()
  otherInvestmentSource: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfKinMiddlename: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfKinLastname: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfKinGender: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfKinFirstname: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfKinPhone: string;

  @ApiProperty({ type: String })
  @IsString()
  @IsEmail()
  nextOfKinEmail: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfkinRelationship: string;

  @ApiProperty({ type: String })
  @IsString()
  otherNextOfKinRelationship: string;

  @ApiProperty({ type: String })
  @IsString()
  addressProofPath: string;

  @ApiProperty({ type: String })
  @IsString()
  signatureImagePath: string;

  @ApiProperty()
  @IsJSON()
  kycCompletionStatus: { [key in KycUpdates]: boolean };


  @ApiProperty({ type: Boolean })
  @IsBoolean()
  zanibarAccountCreated: boolean;


  @ApiProperty({ type: Boolean })
  @IsBoolean()
  isVerified: boolean;

  @ApiProperty({ enum: RoleEnum })
  @IsEnum(RoleEnum)
  role?: RoleEnum;

  @ApiProperty({ enum: StatusEnum })
  @IsEnum(StatusEnum)
  status?: StatusEnum;

  @ApiProperty({type:()=> TransactionEntity})
  my_transactions?: TransactionEntity[];

  @ApiProperty()
  @IsDate()
  createdAt: Date;

  @ApiProperty()
  @IsDate()
  updatedAt: Date;

  @ApiProperty()
  @IsDate()
  @IsOptional()
  deletedAt?: Date;
}
