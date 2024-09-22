import request from 'supertest';
import { APP_URL, TESTER_EMAIL, TESTER_PASSWORD } from '../utils/constants';

import { SmileService } from '../../src/utils/services/smileID.service';
import { PaymentGatewayService } from '../../src/payment/payment.service';

jest.mock('../../src/wallet/payment-gateway.service');
jest.mock('../../src/utils/services/smileID.service');

describe('Wallet Module', () => {
  const app = APP_URL;
  let userToken: string;
  let userId: string;

  beforeAll(async () => {
    // Login to get the token
    const loginResponse = await request(app)
      .post('/api/v1/auth/email/login')
      .send({ email: TESTER_EMAIL, password: TESTER_PASSWORD });
    userToken = loginResponse.body.token;
    userId = loginResponse.body.user.id;
  });

  describe('Fund Account', () => {
    it('should fund account: /api/v1/wallet/fund-account (POST)', async () => {
      const fundingDto = { amount: 1000 };
      (
        PaymentGatewayService.prototype.processPayment as jest.Mock
      ).mockResolvedValue({ success: true });

      return request(app)
        .post('/api/v1/wallet/fund-account')
        .auth(userToken, { type: 'bearer' })
        .send(fundingDto)
        .expect(200)
        .expect((res) => {
          expect(res.body.balance).toBeGreaterThan(0);
          expect(res.body.lastDepositAt).toBeDefined();
        });
    });
  });

  describe('Withdraw Funds', () => {
    it('should withdraw funds: /api/v1/wallet/withdraw-funds (POST)', async () => {
      const withdrawalDto = {
        amount: 500,
        accountNumber: '1234567890',
        bankName: 'Test Bank',
      };
      (SmileService.prototype.verifyBankAccount as jest.Mock).mockResolvedValue(
        true,
      );
      (
        PaymentGatewayService.prototype.processWithdrawal as jest.Mock
      ).mockResolvedValue({ success: true });

      return request(app)
        .post('/api/v1/wallet/withdraw-funds')
        .auth(userToken, { type: 'bearer' })
        .send(withdrawalDto)
        .expect(200)
        .expect((res) => {
          expect(res.body.balance).toBeDefined();
          expect(res.body.lastwithdrawalAt).toBeDefined();
        });
    });
  });

  describe('Add Card', () => {
    it('should add a card: /api/v1/wallet/add-card (POST)', async () => {
      const cardDto = { cardDigits: '4111111111111111' };
      (
        PaymentGatewayService.prototype.tokenizeCard as jest.Mock
      ).mockResolvedValue({
        token: 'mock-token',
        last4Digits: '1111',
        expiryMonth: '12',
        expiryYear: '2025',
        cardType: 'Visa',
      });

      return request(app)
        .post('/api/v1/wallet/add-card')
        .auth(userToken, { type: 'bearer' })
        .send(cardDto)
        .expect(200)
        .expect((res) => {
          expect(res.body.token).toBeDefined();
          expect(res.body.last4Digits).toBe('1111');
          expect(res.body.cardType).toBe('Visa');
        });
    });
  });

  describe('Remove Card', () => {
    it('should remove a card: /api/v1/wallet/remove-card/:cardID (DELETE)', async () => {
      const cardId = 1; // Assuming a card with ID 1 exists

      return request(app)
        .delete(`/api/v1/wallet/remove-card/${cardId}`)
        .auth(userToken, { type: 'bearer' })
        .expect(204);
    });
  });

  describe('Fetch Wallet Balance', () => {
    it('should fetch wallet balance: /api/v1/wallet/fetch-wallet-balance (GET)', async () => {
      return request(app)
        .get('/api/v1/wallet/fetch-wallet-balance')
        .auth(userToken, { type: 'bearer' })
        .expect(200)
        .expect((res) => {
          expect(typeof res.body).toBe('number');
        });
    });
  });

  describe('Get Saved Cards', () => {
    it('should get saved cards: /api/v1/wallet/get-saved-cards (GET)', async () => {
      return request(app)
        .get('/api/v1/wallet/get-saved-cards')
        .auth(userToken, { type: 'bearer' })
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
          if (res.body.length > 0) {
            expect(res.body[0].last4Digits).toBeDefined();
            expect(res.body[0].cardType).toBeDefined();
          }
        });
    });
  });
});
