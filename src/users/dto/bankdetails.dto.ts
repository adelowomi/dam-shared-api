import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator';

export class BankDetailsDto {
  @ApiProperty({ type: String })
  @IsNotEmpty()
  bankcode: string;

  @ApiProperty({ type: String })
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(10)
  accountNumber: string;
}
