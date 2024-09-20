import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsNumber, IsString } from 'class-validator';

export class SmilePartnerParamsModel {
  @ApiProperty({
    type: String,
    description: 'Library version from smile library on the frontend',
  })
  @IsString()
  libraryVersion: string;

  @ApiProperty({
    type: Boolean,
    description: 'Permission granted from frontend',
  })
  @IsBoolean()
  permissionGranted: boolean;
}

export class SmileImageModel {
  @ApiProperty({ type: String, description: 'Image URL' })
  @IsString()
  image: string;

  @ApiProperty({ type: Number, description: 'Image type ID' })
  @IsNumber()
  image_type_id: number;
}

export class PersnalIdVerificationModel {
  @ApiProperty({
    type: Array<SmileImageModel>,
    description: 'images captured from the user on the web sdk',
  })
  images: SmileImageModel[];

  @ApiProperty({
    type: SmilePartnerParamsModel,
    description: 'Partner params from the frontend',
  })
  partner_params: SmilePartnerParamsModel;
}
