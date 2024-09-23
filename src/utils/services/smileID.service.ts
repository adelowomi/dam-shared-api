import { Injectable, Logger } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import * as smileIdentityCore from 'smile-identity-core';
import { ResponseService } from './response.service';
import {
  SmileImageModel,
  SmilePartnerParamsModel,
} from '../../users/dto/personal-id';
import {
  CreateSmileLinkResponse,
  CreateVerificationLinkModel,
} from './models/create-verification-link-model';
import { FetchService } from 'nestjs-fetch';
const Signature = smileIdentityCore.Signature;

@Injectable()
export class SmileService {
  private readonly logger = new Logger(SmileService.name);
  private readonly apiUrl: string;
  private readonly apiKey: string;
  private readonly partnerId: string;
  private readonly sidServer: string;
  private readonly idApi: any;
  private readonly webApi: any;
  private readonly _fetchService: FetchService;

  constructor(
    private responseService: ResponseService,
    private fetchService: FetchService,
  ) {
    if (!process.env.SMILE_API_URL) {
      throw new Error(
        'SMILE_API_URL is not defined in the environment variables',
      );
    }
    if (!process.env.SMILE_API_KEY) {
      throw new Error(
        'SMILE_API_KEY is not defined in the environment variables',
      );
    }
    if (!process.env.SMILE_PARTNER_ID) {
      throw new Error(
        'SMILE_PARTNER_ID is not defined in the environment variables',
      );
    }
    if (!process.env.SMILE_SID_SERVER) {
      throw new Error(
        'SMILE_SID_SERVER is not defined in the environment variables',
      );
    }

    this.apiUrl = process.env.SMILE_API_URL;
    this.apiKey = process.env.SMILE_API_KEY;
    this.partnerId = process.env.SMILE_PARTNER_ID;
    this.sidServer = process.env.SMILE_SID_SERVER;

    // Initialize Smile Identity SDK's IDApi class for ID verification
    this.idApi = new smileIdentityCore.IDApi(
      this.partnerId,
      this.apiKey,
      this.sidServer === '0' ? '0' : '1',
      // Set to true for debugging purposes, set to false in production
    );

    // Initialize Smile Identity SDK's webapi class for ID verification
    this.webApi = new smileIdentityCore.WebApi(
      this.partnerId,
      this.apiKey,
      'http://localhost:3000/api/v1/smile-id/webhooks', //callback url
      this.sidServer === '0' ? '0' : '1',
      // Set to true for debugging purposes, set to false in production
    );
    this._fetchService = fetchService;
  }

  async performIdVerification(
    userId: string,
    idType: string,
    idNumber: string,
    firstname: string,
    lastname: string,
    dob: string,
    phone_number: string,
  ): Promise<any> {
    const jobId = uuidv4();
    const partnerParams = {
      user_id: userId,
      job_id: jobId,
      job_type: 5, // 5 is for ID verification without selfie
    };

    const idInfo = {
      country: 'NG', // Assuming Nigeria, adjust if needed
      id_type: idType,
      id_number: idNumber,
      first_name: firstname,
      last_name: lastname,
      dob: dob, // yyyy-mm-dd
      phone_number: phone_number,
    };
    console.log('🚀 ~ SmileService ~ performIdVerification ~ idInfo:', idInfo);

    const options = {
      return_job_status: true,
      return_history: false,
      return_image_links: false,
    };

    this.logger.debug(
      `Initiating ID verification for user ${userId} with ID type ${idType}`,
    );
    this.logger.debug('idInfo:', idInfo);

    if (!idInfo.id_type || !idInfo.id_number) {
      throw new Error('ID type and ID number are required for verification');
    }

    try {
      const response = await this.idApi.submit_job(
        partnerParams,
        idInfo,
        options,
      );
      this.logger.debug(
        `ID verification response for user ${userId}:`,
        response,
      );
      return this.responseService.success(
        'ID verification successful',
        response,
      );
    } catch (error) {
      console.log('🚀 ~ SmileService ~ performIdVerification ~ error:', error);
      this.logger.error(`ID verification failed for user ${userId}:`, error);
      return this.responseService.internalServerError(
        `ID verification failed`,
        error.message,
      );
    }
  }

  async submitSelfieJob(
    userId: string,
    images: any,
    libraryVersion: string,
  ): Promise<any> {
    const partnerParams = {
      user_id: userId,
      job_id: `job-${uuidv4()}`,
      job_type: 4, // 4 is for the simplest job which enrolls a user using their selfie
    };

    const options = {
      return_job_status: true,
    };

    const combinedParams = { ...partnerParams, libraryVersion };

    try {
      const result = await this.webApi.submit_job(
        combinedParams,
        images,
        {},
        options,
      );
      return this.responseService.success(
        'smart selfie job successful',
        result,
      );
    } catch (error) {
      console.error('Selfie job submission failed:', error);
      return this.responseService.internalServerError(
        `Selfie job submission failed`,
        error.message,
      );
    }
  }

  handleCallback(callbackData: any): void {
    // Logic to process the callback from SmileIdentity
    console.log('Received callback:', callbackData);
  }

  async performBankVerification(
    userId: string,
    accountNumber: string,
    bankCode: string,
  ): Promise<any> {
    const jobId = uuidv4();
    const partnerParams = {
      user_id: userId,
      job_id: jobId,
      job_type: 5, // 5 is for ID verification without selfie
    };

    const idInfo = {
      country: 'NG', // Assuming Nigeria, adjust if needed
      id_type: 'BANK_ACCOUNT',
      id_number: accountNumber,
      bank_code: bankCode,
    };
    console.log('🚀 ~ SmileService ~ performIdVerification ~ idInfo:', idInfo);

    const options = {
      return_job_status: true,
      return_history: false,
      return_image_links: false,
    };

    this.logger.debug(
      `Initiating ID verification for user ${userId} with ID type ${idInfo.id_type}`,
    );
    this.logger.debug('idInfo:', idInfo);

    if (!idInfo.id_type || !idInfo.id_number) {
      throw new Error('ID type and ID number are required for verification');
    }

    try {
      const response = await this.idApi.submit_job(
        partnerParams,
        idInfo,
        options,
      );
      this.logger.debug(
        `ID verification response for user ${userId}:`,
        response,
      );
      return this.responseService.success('ID verification ', response);
    } catch (error) {
      console.log('🚀 ~ SmileService ~ performIdVerification ~ error:', error);
      this.logger.error(`ID verification failed for user ${userId}:`, error);
      return this.responseService.internalServerError(
        `ID verification failed`,
        error.message,
      );
    }
  }

  verifyWebhook(authorizationHeader: string, payload: any): boolean {
    console.log('🚀 ~ SmileService ~ verifyWebhook ~ payload:', payload);
    // Check the authorization header or signature if required by SmileID
    const expectedAuthHeader = `Bearer ${this.apiKey}`;
    return authorizationHeader === expectedAuthHeader;
  }

  async selfieAndImageIdentityVerification({
    images,
    partner_params,
  }: {
    images: SmileImageModel[];
    partner_params: SmilePartnerParamsModel;
  }): Promise<any> {
    const partner_params_from_server = {
      user_id: `user-${uuidv4()}`,
      job_id: `job-${uuidv4()}`,
      job_type: 4, // job_type is the simplest job we have which enrolls a user using their selfie
      library_version: partner_params.libraryVersion,
    };

    const options = {
      return_job_status: true,
    };

    const result = await this.webApi.submit_job(
      partner_params_from_server,
      images,
      {},
      options,
    );

    return result;
  }

  async computeSignature(): Promise<string> {
    // const signatureConnection = new Signature(this.partnerId, this.apiKey)
    const signatureConnection = new Signature(
      '6722',
      'e2314915-c72e-443c-9ca7-3a4408117da4',
    );

    const generated_signature = signatureConnection.generate_signature();
    return generated_signature.signature;
  }

  async confirmIncomingSignature({
    signature,
    timestamp,
  }: {
    signature: string;
    timestamp: string;
  }): Promise<boolean> {
    const signatureConnection = new Signature(this.partnerId, this.apiKey);
    const isSignatureValid = signatureConnection.confirm_signature(
      signature,
      timestamp,
    );
    return isSignatureValid;
  }

  async createSmileLink({
    model,
  }: {
    model: CreateVerificationLinkModel;
  }): Promise<CreateSmileLinkResponse> {
    model.signature = await this.computeSignature();
    model.partner_id = '6722';
    model.timestamp = new Date().toISOString();
    model.expires_at = new Date(
      new Date().getTime() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    model.callback_url = `https://stg.dam.api.sofriwebservices.com/api/v1/kyc/smile-webhook`;
    model.name = 'DLM Asset Management';
    model.company_name = 'LINKS MICROFINANCE BANK';
    model.data_privacy_policy_url = 'https://dlm.group/privacy-policy/';
    model.logo_url =
      'https://dlm.group/wp-content/uploads/2019/07/DLM-Capital-Group-Logo-2-768x291.png';
    model.is_single_use = true;
    model.id_types = [
      // {
      //   country: 'NG',
      //   id_type: 'IDENTITY_CARD',
      //   verification_method: 'OTP',
      // },
      {
        country: 'NG',
        id_type: 'PASSPORT',
        verification_method: 'doc_verification',
      },
      // {
      //   country: 'NG',
      //   id_type: 'TRAVEL_DOC',
      //   verification_method: 'OTP',
      // },
    ];
    const response = await this._fetchService.post(
      `${process.env.SMILE_API_URL}/v1/smile_links`,
      {
        body: JSON.stringify(model),
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
      },
    );
    const result = await response.json();
    result.success = true;
    return result;
  }
}
