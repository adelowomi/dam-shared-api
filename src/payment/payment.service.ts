import { Injectable } from '@nestjs/common';
import axios from 'axios';

@Injectable()
//sofri bank api 
export class PaymentGatewayService {
  private readonly apiUrl = 'https://api.sofrisofri.com/v1'; // we can Replace with actual Sofri Bank API URL later
  private readonly apiKey = 'SOFRI_BANK_API_KEY'; // Replace with your actual API key

  async processPayment(amount: number): Promise<{ success: boolean; transactionId?: string }> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/payments`,
        {
          amount,
          currency: 'NGN', // we can adjust as needed
        },
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (response.data.status === 'success') {
        return { success: true, transactionId: response.data.transactionId };
      } else {
        return { success: false };
      }
    } catch (error) {
      console.error('Payment processing error:', error);
      return { success: false };
    }
  }

  async tokenizeCard(cardDetails: any): Promise<{ token: string; last4Digits: string; expiryMonth: string; expiryYear: string; cardType: string }> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/tokenize`,
        cardDetails,
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
          },
        }
      );

      return {
        token: response.data.token,
        last4Digits: response.data.last4,
        expiryMonth: response.data.expiryMonth,
        expiryYear: response.data.expiryYear,
        cardType: response.data.cardType,
      };
    } catch (error) {
      console.error('Card tokenization error:', error);
      throw new Error('Failed to tokenize card');
    }
  }

  async processWithdrawal(amount: number, accountNumber: string): Promise<{ success: boolean; transactionId?: string }> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/withdrawals`,
        {
          amount,
          accountNumber,
          currency: 'NGN', // Assuming Nigerian Naira, adjust as needed
        },
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (response.data.status === 'success') {
        return { success: true, transactionId: response.data.transactionId };
      } else {
        return { success: false };
      }
    } catch (error) {
      console.error('Withdrawal processing error:', error);
      return { success: false };
    }
  }
}