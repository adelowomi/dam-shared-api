import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class AuthresendOtpDto {
  
  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
