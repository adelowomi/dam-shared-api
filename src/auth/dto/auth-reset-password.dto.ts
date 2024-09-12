import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsStrongPassword } from 'class-validator';
import { Match } from '../../utils/custom-decorator';

export class AuthResetPasswordDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsStrongPassword({minLength:6,minLowercase:1,minNumbers:1,minSymbols:1,minUppercase:1,})
  password: string;

  @ApiProperty({type:String})
  @IsNotEmpty()
  @Match('password', { message: 'confirmPassword does not match the password.' })
  confirmPassword: string;


  @ApiProperty()
  @IsNotEmpty()
  hash: string;

  @ApiProperty()
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
