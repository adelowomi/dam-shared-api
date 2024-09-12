import { Transform, Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsDateString,
  // decorators here
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsStrongPassword,
  MinLength,
} from 'class-validator';
import { FileDto } from '../../files/dto/file.dto';
import { lowerCaseTransformer } from '../../utils/transformers/lower-case.transformer';
import { Match } from '../../utils/custom-decorator';

export class CreateUserDto {
  @ApiProperty({ example: 'test1@example.com', type: String })
  @Transform(lowerCaseTransformer)
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsStrongPassword({
    minLength: 6,
    minLowercase: 1,
    minUppercase: 1,
    minSymbols: 1,
    minNumbers: 1,
  })
  password: string;

  @ApiProperty({ type: String })
  @IsNotEmpty()
  @Match('password', {
    message: 'confirmPassword does not match the password.',
  })
  confirmPassword: string;

  @ApiProperty({ example: 'miss, ms, mr, mrs', type: String })
  @IsNotEmpty()
  title: string;

  @ApiProperty({ example: 'John', type: String })
  @IsNotEmpty()
  firstName: string | null;

  @ApiProperty({ example: 'Doe', type: String })
  @IsNotEmpty()
  lastName: string;

  @ApiPropertyOptional({ example: 'Sam', type: String })
  @IsOptional()
  middleName: string;

  @ApiProperty({ example: '0901230005', type: String })
  @IsNotEmpty()
  phoneNumber: string | null;

  @ApiProperty({ example: 'kaduna', type: String })
  @IsNotEmpty()
  stateOfResidence: string;

  @ApiProperty({ example: 'Nigeria', type: String })
  @IsNotEmpty()
  countryOfResidence: string;

  @ApiProperty({ example: '45 abc street', type: String })
  @IsNotEmpty()
  address: string;

  @ApiProperty({ example: 'male,female', type: String })
  @IsNotEmpty()
  gender: string;

  @ApiProperty({ example: '1997/03/01', type: String })
  @IsNotEmpty()
  @IsDateString()
  DOB: string;

  hash?: string | null;
}
