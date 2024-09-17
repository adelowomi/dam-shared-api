import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import * as smileIdentityCore from 'smile-identity-core';

@Injectable()
export class SmileService {
  private readonly logger = new Logger(SmileService.name);
  private readonly apiUrl: string;
  private readonly apiKey: string;
  private readonly partnerId: string;
  private readonly sidServer: string;
  private readonly idApi: any;
  private readonly webApi: any;

  constructor() {
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
      return response;
    } catch (error) {
      console.log('🚀 ~ SmileService ~ performIdVerification ~ error:', error);
      this.logger.error(`ID verification failed for user ${userId}:`, error);
      throw new Error(`ID verification failed: ${error.message}`);
    }
  }

  async submitSelfieJob( userId: string,images: any, libraryVersion: string): Promise<any> {
    const partnerParams = {
      user_id:userId,
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
      return result;
    } catch (error) {
      console.error('Selfie job submission failed:', error);
      throw new Error(`Selfie job submission failed: ${error.message}`);
    }
  }

  handleCallback(callbackData: any): void {
    // Logic to process the callback from SmileIdentity
    console.log('Received callback:', callbackData);
  }

 

  async verifyBankAccount(
    bankName: string,
    accountNumber: string,
  ): Promise<any> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/bank_account_verification`,
        { bank_name: bankName, account_number: accountNumber },
        {
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.apiKey}`,
          },
        },
      );
      return response.data;
    } catch (error) {
      throw new Error(`Bank account verification failed: ${error.message}`);
    }
  }



  verifyWebhook(authorizationHeader: string, payload: any): boolean {
    // Check the authorization header or signature if required by SmileID
    const expectedAuthHeader = `Bearer ${this.apiKey}`;
    return authorizationHeader === expectedAuthHeader;
  }
}
