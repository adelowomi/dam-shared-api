import { Injectable } from '@nestjs/common';
import { PayStackService } from '../utils/services/paystack.service';
import { PayStackBank } from '../utils/services/models/PayStaackStandardResponse';
import {
  StandardResponse,
  ResponseService,
} from '../utils/services/response.service';

@Injectable()
export class UtilitiesService {
  constructor(
    private readonly payStackService: PayStackService,
    private readonly responseService: ResponseService,
  ) {}

  getBanks = async (): Promise<StandardResponse<PayStackBank[]>> => {
    const response = await this.payStackService.getBanks();
    return this.responseService.success(response.message, response.data);
  };
}
