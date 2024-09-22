import { ApiProperty } from '@nestjs/swagger';

export class PayStaackStandardResponse<T> {
  @ApiProperty({ type: Boolean })
  status: boolean;

  @ApiProperty({ type: String })
  message: string;

  @ApiProperty({ type: Object })
  data: T;

  constructor(status: boolean, message: string, data: T) {
    this.status = status;
    this.message = message;
    this.data = data;
  }
}

export interface ResolveBankAccountResponse {
  account_number: string;
  account_name: string;
  bank_id: number;
}

export interface PayStackBank {
  name: string;
  slug: string;
  code: string;
  longcode: string;
  gateway: string | null;
  pay_with_bank: boolean;
  active: boolean;
  is_deleted: boolean;
  country: string;
  currency: string;
  type: string;
  id: number;
  createdAt: string;
  updatedAt: string;
}
