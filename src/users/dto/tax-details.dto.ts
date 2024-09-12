import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class TaxDetailsDto {
  @ApiProperty({ type: String })
  @IsString()
  @IsNotEmpty()
  taxLocation: string;

  @ApiProperty({ type: String, example: '' })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[A-Za-z0-9-]+$/, {
    message:
      'Tax Identity Number can only contain alphanumeric characters and hyphens',
  })
  taxIdentityNumber: string;
}
