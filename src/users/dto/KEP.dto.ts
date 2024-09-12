import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsDateString, IsNotEmpty } from 'class-validator';

export class PepDto {
  @ApiProperty({ example: 'true, false', type: Boolean })
  @IsNotEmpty()
  @IsBoolean()
  PEP: boolean;
}
