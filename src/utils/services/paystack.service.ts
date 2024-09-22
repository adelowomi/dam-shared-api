import { FetchService } from 'nestjs-fetch';
import { CustomFetchService } from './CustomFetchService';
import { PayStackConfig } from './models/PayStackConfig';
import { Injectable } from '@nestjs/common';
import {
  PayStaackStandardResponse,
  PayStackBank,
  ResolveBankAccountResponse,
} from './models/PayStaackStandardResponse';

@Injectable()
export class PayStackService {
  private readonly _fetchService: CustomFetchService;
  private readonly _config: PayStackConfig;
  constructor(
    private fetchService: FetchService,
    private customFetchService: CustomFetchService,
  ) {
    // set api key in the headers
    this._config = PayStackConfig.fromEnv();
    this._fetchService = this.customFetchService;
    this._fetchService.init({
      'Content-Type': 'application/json',
      Authorization: `Bearer ${this._config.secretKey}`,
    });
  }

  // use arrow function to bind this to the class
  public resolveBankAccount = async (
    accountNumber: string,
    bankCode: string,
  ): Promise<PayStaackStandardResponse<ResolveBankAccountResponse>> => {
    console.log('Paystack confg', this._config);
    const response = await this._fetchService.get<
      PayStaackStandardResponse<ResolveBankAccountResponse>
    >(`${this._config.baseUrl}/bank/resolve`, {
      account_number: accountNumber,
      bank_code: bankCode,
    });

    console.log('🚀 ~ PayStackService ~ response:', response);

    return response.data!;
  };

  public getBanks = async (): Promise<
    PayStaackStandardResponse<PayStackBank[]>
  > => {
    const response = await this._fetchService.get<
      PayStaackStandardResponse<PayStackBank[]>
    >(`${this._config.baseUrl}/bank`);

    return response.data!;
  };
}
