import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsDateString,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateIf,
} from 'class-validator';

enum documentType {
  UTILITY_BILL = 'utility_bill',
  BANK_STATEMENT = 'bank_statement',
  GOVERNMENT_LETTER = 'government_letter',
  OTHER = 'other',
}
export class AddressProofDto {
  @ApiProperty({ type: String })
  @IsDateString()
  @IsNotEmpty()
  documentDate: Date;

  @ApiProperty({ enum: documentType })
  @IsEnum(documentType)
  @IsNotEmpty()
  documentType: string;

  @ApiProperty({ type: String })
  @ValidateIf((o) => o.documentType === documentType.OTHER)
  @IsString()
  @IsOptional()
  otherDocumentType?: string;
}
