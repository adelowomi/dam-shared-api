import { Injectable } from '@nestjs/common';
import axios from 'axios';

@Injectable()
export class SmileService {
  private readonly apiUrl: string;
  private readonly apiKey: string;

  constructor() {
    if (!process.env.SMILE_API_URL) {
      throw new Error('SMILE_API_URL is not defined in the environment variables');
    }
    if (!process.env.SMILE_API_KEY) {
      throw new Error('SMILE_API_KEY is not defined in the environment variables');
    }
    
    this.apiUrl = process.env.SMILE_API_URL;
    this.apiKey = process.env.SMILE_API_KEY;
  }

  async verifyBVN(bvn: string): Promise<any> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/bvn_verification`,
        { bvn },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`BVN verification failed: ${error.message}`);
    }
  }

  async verifyNIN(nin: string): Promise<any> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/nin_verification`,
        { nin },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`NIN verification failed: ${error.message}`);
    }
  }

  async initiatePassportPhotographVerification(userId: string): Promise<string> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/passport_photograph_verification/initiate`,
        { user_id: userId },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data.redirect_url;
    } catch (error) {
      throw new Error(`Failed to initiate passport photograph verification: ${error.message}`);
    }
  }

  async verifyPassportPhotographSession(sessionId: string): Promise<any> {
    try {
      const response = await axios.get(
        `${this.apiUrl}/passport_photograph_verification/verify/${sessionId}`,
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to verify passport photograph session: ${error.message}`);
    }
  }

  async verifyGovernmentId(idType: string, idNumber: string, expirationDate: string): Promise<any> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/government_id_verification`,
        { id_type: idType, id_number: idNumber, expiration_date: expirationDate },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Government ID verification failed: ${error.message}`);
    }
  }

  async verifyAddressProof(documentType: string, documentDate: string, documentImage: string): Promise<any> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/address_proof_verification`,
        { document_type: documentType, document_date: documentDate, document_image: documentImage },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Address proof verification failed: ${error.message}`);
    }
  }

  async verifyBankAccount(bankName: string, accountNumber: string): Promise<any> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/bank_account_verification`,
        { bank_name: bankName, account_number: accountNumber },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Bank account verification failed: ${error.message}`);
    }
  }

  async verifyTaxDetails(taxLocation: string, taxIdentityNumber: string): Promise<any> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/tax_details_verification`,
        { tax_location: taxLocation, tax_identity_number: taxIdentityNumber },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Tax details verification failed: ${error.message}`);
    }
  }


}