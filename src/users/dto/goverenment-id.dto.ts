import { ApiProperty } from '@nestjs/swagger';
import { IsDateString, IsEnum, IsNotEmpty, IsString } from 'class-validator';

export class GovernmentIdDto {
  @ApiProperty({
    enum: ['drivers_license', 'international_passport', 'national'],
  })
  @IsEnum(['drivers_license', 'international_passport', 'national_id'])
  @IsNotEmpty()
  idType: string;

  @ApiProperty({ type: String })
  @IsString()
  @IsNotEmpty()
  idNumber: string;

  @ApiProperty({ type: String })
  @IsDateString()
  @IsNotEmpty()
  expirationDate: string;
}
