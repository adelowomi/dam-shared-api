import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator';

export class BankDetailsDto {
  @ApiProperty({ type: String })
  @IsNotEmpty()
  bankName: string;

  @ApiProperty({ type: String })
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(20)
  accountNumber: string;
}
