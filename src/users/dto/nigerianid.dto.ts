import { IsString, Matches, ValidateIf, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum NigerianIdEnum {
  NIN = 'NIN',
  VOTER_ID = 'VOTER_ID',
  PHONE_NUMBER = 'PHONE_NUMBER',
  BVN = 'BVN',
  NIN_V2 = 'NIN_V2'
}

export class NigerianIdDto {
  @ApiProperty({ enum: NigerianIdEnum, description: 'Type of ID' })
  @IsEnum(NigerianIdEnum)
  idType!: NigerianIdEnum;

  @ApiProperty({ type: String, description: 'BVN (11 digits)', required: false })
  @IsString()
  @Matches(/^[0-9]{11}$/, { message: 'BVN must be an 11-digit number' })
  @ValidateIf(o => o.idType === NigerianIdEnum.BVN)
  bvn?: string;

  @ApiProperty({ type: String, description: 'NIN V2 (11 digits)', required: false })
  @IsString()
  @Matches(/^[0-9]{11}$/, { message: 'NIN must be an 11-digit number' })
  @ValidateIf(o => o.idType === NigerianIdEnum.NIN_V2)
  nin_v2?: string;

  @ApiProperty({ type: String, description: 'NIN Slip (11 digits)', required: false })
  @IsString()
  @Matches(/^[0-9]{11}$/, { message: 'NIN Slip must be an 11-digit number' })
  @ValidateIf(o => o.idType === NigerianIdEnum.NIN)
  nin_slip?: string;

  @ApiProperty({ type: String, description: 'Phone number (11 digits)', required: false })
  @IsString()
  @Matches(/^[0-9]{11}$/, { message: 'Phone number must be an 11-digit number' })
  @ValidateIf(o => o.idType === NigerianIdEnum.PHONE_NUMBER)
  phone_number?: string;

  @ApiProperty({ type: String, description: 'Voter ID (9-29 alphanumeric characters)', required: false })
  @IsString()
  @Matches(/^[a-zA-Z0-9 ]{9,29}$/i, { message: 'Voter ID must be between 9 and 29 alphanumeric characters' })
  @ValidateIf(o => o.idType === NigerianIdEnum.VOTER_ID)
  voter_id?: string;
}