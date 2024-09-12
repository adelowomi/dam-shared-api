import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEnum,
  IsString,
  IsEmail,
  IsPhoneNumber,
  IsOptional,
  ValidateIf,
} from 'class-validator';

enum NextofKinRelationship {
  CHILD = 'child',
  PARENT = 'parent',
  SIBLING = 'sibling',
  SPOUSE = 'spouse',
  OTHER = 'Other',
}

export class NextOfKinDto {
  @ApiPropertyOptional({ type: String })
  @IsString()
  nextOfKinMiddlename: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfKinFirstname: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfKinLastname: string;

  @ApiProperty({ type: String })
  @IsString()
  nextOfKinGender: string;

  @ApiProperty({ type: String })
  @IsEmail()
  nextOfKinEmail: string;

  @ApiProperty({ type: String })
  @IsPhoneNumber('NG')
  nextOfKinPhone: string;

  @ApiProperty({ enum: NextofKinRelationship })
  @IsEnum(NextofKinRelationship)
  nextofkinRelationship: NextofKinRelationship;

  @ApiProperty({ type: String })
  @ValidateIf((o) => o.NextofKinRelationship === NextofKinRelationship.OTHER)
  @IsString()
  otherNextOfKinRelatioship: string;
}
