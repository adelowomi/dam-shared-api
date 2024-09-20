import { IsString, IsNumber } from 'class-validator';

export class Actions {
  @IsString()
  Document_Check: string;

  @IsString()
  Human_Review_Compare: string;

  @IsString()
  Human_Review_Document_Check: string;

  @IsString()
  Human_Review_Liveness_Check: string;

  @IsString()
  Liveness_Check: string;

  @IsString()
  Register_Selfie: string;

  @IsString()
  Return_Personal_Info: string;

  @IsString()
  Selfie_To_ID_Card_Compare: string;

  @IsString()
  Verify_Document: string;
}

export class ImageLinks {
  @IsString()
  id_card_image: string;

  @IsString()
  selfie_image: string;
}

export class PartnerParams {
  @IsString()
  job_id: string;

  @IsNumber()
  job_type: number;

  @IsString()
  link_id: string;

  @IsString()
  user_id: string;
}

export class SmileJobWebHookDto {
  @IsString()
  Country: string;

  @IsString()
  DOB: string;

  @IsString()
  Document: string;

  @IsString()
  ExpirationDate: string;

  @IsString()
  FirstName: string;

  @IsString()
  FullName: string;

  @IsString()
  Gender: string;

  @IsString()
  IDNumber: string;

  @IsString()
  IDType: string;

  ImageLinks: ImageLinks;

  @IsString()
  IssuanceDate: string;

  @IsString()
  KYCReceipt: string;

  @IsString()
  LastName: string;

  @IsString()
  OtherName: string;

  PartnerParams: PartnerParams;

  @IsString()
  PhoneNumber2: string;

  @IsString()
  ResultCode: string;

  @IsString()
  ResultText: string;

  @IsString()
  SecondaryIDNumber: string;

  @IsString()
  signature: string;

  @IsString()
  SmileJobID: string;

  @IsString()
  timestamp: string;

  Actions: Actions;
}
