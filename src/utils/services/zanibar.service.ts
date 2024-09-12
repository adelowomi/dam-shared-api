import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { UserEntity } from '../../users/infrastructure/persistence/relational/entities/user.entity';

@Injectable()
export class ZanzibarService {
  private readonly apiUrl: string;
  private readonly apiKey: string;

  constructor() {
    if (!process.env.ZANIBAR_API_URL) {
      throw new Error('ZANIBAR_API_URL is not defined in the environment variables');
    }
    if (!process.env.ZANIBAR_API_KEY) {
      throw new Error('ZANIBAR_API_KEY is not defined in the environment variables');
    }
    
    this.apiUrl = process.env.ZANIBAR_API_URL;
    this.apiKey = process.env.ZANIBAR_API_KEY;
  }

  async createAccount(user: UserEntity): Promise<any> {
    try {
      const response = await axios.post(
        `${this.apiUrl}/accounts`,
        {
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          // Add any other required fields for Zanzibar account creation
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Zanzibar account creation failed: ${error.message}`);
    }
  }
}