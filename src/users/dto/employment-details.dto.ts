import { ApiProperty } from '@nestjs/swagger';
import {
  IsEnum,
  IsString,
  IsEmail,
  IsPhoneNumber,
  IsOptional,
  ValidateIf,
} from 'class-validator';

enum EmploymentStatus {
  FULL_TIME = 'Full-time employed',
  PART_TIME = 'Part-time employed',
  SELF_EMPLOYED = 'Self-employed',
  UNEMPLOYED = 'Unemployed',
  RETIRED = 'Retired',
  STUDENT = 'Student',
}

enum IncomeBand {
  BELOW_1M = 'Below ₦1,000,000',
  BETWEEN_1M_5M = '₦1,000,000 - ₦5,000,000',
  BETWEEN_5M_10M = '₦5,000,001 - ₦10,000,000',
  BETWEEN_10M_20M = '₦10,000,001 - ₦20,000,000',
  ABOVE_20M = 'Above ₦20,000,000',
}

enum InvestmentSource {
  EMPLOYMENT = 'Employment Income',
  BUSINESS = 'Business Income',
  INVESTMENTS = 'Investments',
  INHERITANCE = 'Inheritance',
  OTHER = 'Other',
}

export class EmploymentDetailsDto {
  @ApiProperty({ enum:EmploymentStatus })
  @IsEnum(EmploymentStatus)
  employmentStatus: EmploymentStatus;

  @ApiProperty({ type: String })
  @ValidateIf((o) =>
    ['Full-time employed', 'Part-time employed', 'Self-employed'].includes(
      o.employmentStatus,
    ),
  )
  @IsString()
  companyName: string;

  @ApiProperty({ type: String })
  @ValidateIf((o) =>
    ['Full-time employed', 'Part-time employed', 'Self-employed'].includes(
      o.employmentStatus,
    ),
  )
  @IsString()
  jobTitle: string;

  @ApiProperty({ type: String })
  @ValidateIf((o) =>
    ['Full-time employed', 'Part-time employed', 'Self-employed'].includes(
      o.employmentStatus,
    ),
  )
  @IsEmail()
  companyEmail: string;

  @ApiProperty({ type: String })
  @ValidateIf((o) =>
    ['Full-time employed', 'Part-time employed', 'Self-employed'].includes(
      o.employmentStatus,
    ),
  )
  @IsPhoneNumber('NG')
  companyPhone: string;

  @ApiProperty({ enum:IncomeBand })
  @ValidateIf((o) =>
    ['Full-time employed', 'Part-time employed', 'Self-employed'].includes(
      o.employmentStatus,
    ),
  )
  @IsEnum(IncomeBand)
  incomeBand: IncomeBand;

  @ApiProperty({ enum:InvestmentSource })
  @IsEnum(InvestmentSource)
  investmentSource: InvestmentSource;

  @ApiProperty({ type: String })
  @ValidateIf((o) => o.investmentSource === InvestmentSource.OTHER)
  @IsString()
  otherInvestmentSource: string;
}
