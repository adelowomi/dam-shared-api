import { ApiProperty } from '@nestjs/swagger';
import { StatusEnum } from '../../../statuses/statuses.enum';
import { RoleEnum } from '../../../roles/roles.enum';
import { FileEntity } from '../../../files/infrastructure/persistence/relational/entities/file.entity';
import { WalletEntity } from '../../infrastructure/persistence/relational/entities/wallet.entity';
import { EmploymentDetailsEntity } from '../../infrastructure/persistence/relational/entities/employmentDetails.entity';
import { BankDetailsEntity } from '../../infrastructure/persistence/relational/entities/bankDetails.entity';
import { NoxtOfKinEntity } from '../../infrastructure/persistence/relational/entities/noxtOfKin.entity';
import { TaxDetailsEntity } from '../../infrastructure/persistence/relational/entities/taxDetails.entity';
import { KycUpdates } from '../../kyc/kyc.enum';
import { AutoMap } from '@automapper/classes';

export class UserView {
  @ApiProperty({ type: Number })
  @AutoMap()
  id: number;

  @ApiProperty({ type: String, example: 'john.doe@example.com' })
  @AutoMap()
  email: string;

  @ApiProperty({ type: String, example: 'miss, ms, mr, mrs' })
  @AutoMap()
  title: string;

  @ApiProperty({ type: String, example: 'Sam' })
  @AutoMap()
  middleName: string;

  @ApiProperty({ type: String, example: 'John' })
  @AutoMap()
  firstName: string;

  @ApiProperty({ type: String, example: 'Doe' })
  @AutoMap()
  lastName: string;

  @ApiProperty({ type: String, example: '1997/03/01' })
  @AutoMap()
  DOB: string;

  @ApiProperty({ type: Number })
  @AutoMap()
  age: number;

  @ApiProperty({ type: String, example: 'male, female' })
  @AutoMap()
  gender: string;

  @ApiProperty({ type: String, example: '45 abc street' })
  @AutoMap()
  address: string;

  @ApiProperty({ type: String, example: '+234901230005' })
  @AutoMap()
  phoneNumber: string;

  @ApiProperty({ type: String, example: 'kaduna' })
  @AutoMap()
  stateOfResidence: string;

  @ApiProperty({ type: String, example: 'Nigeria' })
  @AutoMap()
  countryOfResidence: string;

  @ApiProperty({ type: () => FileEntity })
  @AutoMap()
  photo?: FileEntity | null;

  @ApiProperty({ enum: RoleEnum })
  @AutoMap()
  role: RoleEnum;

  @ApiProperty({ enum: StatusEnum })
  @AutoMap()
  status?: StatusEnum;

  @ApiProperty()
  @AutoMap()
  PEP: boolean;

  @ApiProperty()
  @AutoMap()
  PEPisdone: boolean;

  @ApiProperty({ type: String })
  @AutoMap()
  employmentStatus: string;

  @ApiProperty()
  @AutoMap()
  employmentStatusIsdone: boolean;

  @ApiProperty()
  @AutoMap()
  bankdetaislprovidedIsdone: boolean;

  @ApiProperty({ type: Boolean })
  @AutoMap()
  bankVerified: boolean;

  @ApiProperty()
  @AutoMap()
  taxdetailsprovidedIsdone: boolean;

  @ApiProperty()
  @AutoMap()
  employmentdetailsProvidedIsdone: boolean;

  @ApiProperty()
  @AutoMap()
  nextofkinDetailsprovidedIsdone: boolean;

  @ApiProperty({ type: String })
  @AutoMap()
  addressProofPath: string;

  @ApiProperty()
  @AutoMap()
  addressProofProvidedIsdone: boolean;

  @ApiProperty()
  @AutoMap()
  governmentIdVerifiedIsdone: boolean;

  @ApiProperty()
  @AutoMap()
  smartPhotographyIsdone: boolean;

  @ApiProperty()
  @AutoMap()
  signatureUploadedIsdone: boolean;

  @ApiProperty()
  @AutoMap()
  registerAndVerifiedIsdone: boolean;

  @ApiProperty()
  @AutoMap()
  kycCompletionStatus: { [key in KycUpdates]: boolean };

  @ApiProperty()
  @AutoMap()
  zanibarAccountCreated: boolean;

  @ApiProperty()
  @AutoMap()
  isVerified: boolean;

  @ApiProperty()
  @AutoMap()
  signatureImagePath: string;

  @ApiProperty()
  @AutoMap()
  createdAt: Date;

  @ApiProperty()
  @AutoMap()
  updatedAt: Date;

  @ApiProperty()
  @AutoMap()
  deletedAt: Date;

  my_wallet: WalletEntity;

  employmentDetails: EmploymentDetailsEntity;

  bankDetails: BankDetailsEntity;
  // This side owns the foreign key
  nextOfKins: NoxtOfKinEntity;
  // This side owns the foreign key
  taxDetails: TaxDetailsEntity;
}
