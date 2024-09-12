import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsDateString, IsEmail, IsNotEmpty, IsOptional, IsStrongPassword, Matches, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';
import { lowerCaseTransformer } from '../../utils/transformers/lower-case.transformer';
import { Match } from '../../utils/custom-decorator';

export class AuthRegisterDto {
  @ApiProperty({ example: 'test1@example.com', type: String })
  @Transform(lowerCaseTransformer)
  @IsEmail()
  email: string;

  @ApiProperty({type:String})
  @IsStrongPassword({minLength:6, minLowercase:1, minUppercase:1,minSymbols:1,minNumbers:1})
  password: string;


  @ApiProperty({type:String})
  @IsNotEmpty()
  @Match('password', { message: 'confirmPassword does not match the password.' })
  confirmPassword: string;

  @ApiProperty({ example: 'miss, ms, mr, mrs',type:String })
  @IsNotEmpty()
  title: string;


  @ApiProperty({ example: 'John',type:String })
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({ example: 'Doe',type: String})
  @IsNotEmpty()
  lastName: string;

  @ApiPropertyOptional({ example: 'Sam', type:String })
  @IsOptional()
  middleName: string;

  @ApiProperty({ example: '+2348012345678', type: String })
  @IsNotEmpty()
  @Matches(/^\+234[789][01]\d{8}$/, {
    message: 'Phone number must be a valid Nigerian number starting with +234',
  })
  phoneNumber: string;


  @ApiProperty({ example: 'kaduna', type:String })
  @IsNotEmpty()
  stateOfResidence: string

  @ApiProperty({ example: 'Nigeria', type:String })
  @IsNotEmpty()
  countryOfResidence: string

  @ApiProperty({ example: '45 abc street', type:String })
  @IsNotEmpty()
  address: string

  @ApiProperty({ example: 'male,female', type:String })
  @IsNotEmpty()
  gender: string

  @ApiProperty({ example: '1997/03/01', type:String })
  @IsNotEmpty()
  @IsDateString()
  DOB: string
}
