import request from 'supertest';
import {
  APP_URL,
  TESTER_EMAIL,
  TESTER_PASSWORD,
  MAIL_HOST,
  MAIL_PORT,
} from '../utils/constants';
import { SmileService } from '../../src/utils/services/smileID.service';
import { FilesS3Service } from '../../src/files/infrastructure/uploader/s3/files.service';

jest.mock('../utils/services/smileID.service');
jest.mock('../files/infrastructure/uploader/s3/files.service');

describe('KYC Module', () => {
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

  describe('Passport Photograph Verification', () => {
    it('should initiate passport photograph verification: /api/v1/kyc/initiatiate-passportPhotograph-verification (POST)', async () => {
      const mockRedirectUrl = 'https://example.com/verify';
      (
        SmileService.prototype
          .initiatePassportPhotographVerification as jest.Mock
      ).mockResolvedValue(mockRedirectUrl);

      return request(app)
        .post('/api/v1/kyc/initiatiate-passportPhotograph-verification')
        .auth(userToken, { type: 'bearer' })
        .expect(200)
        .expect((res) => {
          expect(res.body).toBe(mockRedirectUrl);
        });
    });

    it('should complete passport photograph verification: /api/v1/kyc/complete-passport-photograph-verification (PATCH)', async () => {
      const mockSessionId = 'mock-session-id';
      (
        SmileService.prototype.verifyPassportPhotographSession as jest.Mock
      ).mockResolvedValue({ success: true });

      return request(app)
        .patch('/api/v1/kyc/complete-passport-photograph-verification')
        .auth(userToken, { type: 'bearer' })
        .send({ sessionId: mockSessionId })
        .expect(200)
        .expect((res) => {
          expect(res.body.passportPhotographVerificationInitiated).toBe(false);
          expect(res.body.kycCompletionPercentage).toBeGreaterThan(0);
        });
    });
  });

  describe('Signature Upload', () => {
    it('should upload signature: /api/v1/kyc/upload-signature (PATCH)', async () => {
      const mockFile = {
        buffer: Buffer.from('mock-file'),
        originalname: 'signature.jpg',
      };
      (FilesS3Service.prototype.create as jest.Mock).mockResolvedValue({
        file: { path: 'mock-path' },
      });

      return request(app)
        .patch('/api/v1/kyc/upload-signature')
        .auth(userToken, { type: 'bearer' })
        .attach('signature', mockFile.buffer, mockFile.originalname)
        .expect(200)
        .expect((res) => {
          expect(res.body.signatureImagePath).toBe('mock-path');
          expect(res.body.signatureUploaded).toBe(true);
          expect(res.body.kycCompletionPercentage).toBeGreaterThan(0);
        });
    });
  });

  describe('PEP Details', () => {
    it('should update PEP details: /api/v1/kyc/update-pep-details (PATCH)', async () => {
      const pepDetails = { PEP: true };

      return request(app)
        .patch('/api/v1/kyc/update-pep-details')
        .auth(userToken, { type: 'bearer' })
        .send(pepDetails)
        .expect(200)
        .expect((res) => {
          expect(res.body.PEP).toBe(true);
          expect(res.body.PEPupdated).toBe(true);
          expect(res.body.kycCompletionPercentage).toBeGreaterThan(0);
        });
    });
  });

  describe('Employment Details', () => {
    it('should update employment details: /api/v1/kyc/update-employment-details (PATCH)', async () => {
      const employmentDetails = {
        employmentStatus: 'Employed',
        companyName: 'Test Company',
        jobTitle: 'Software Engineer',
        companyEmail: 'test@company.com',
        companyPhone: '1234567890',
        incomeBand: '50000-100000',
        investmentSource: 'Salary',
      };

      return request(app)
        .patch('/api/v1/kyc/update-employment-details')
        .auth(userToken, { type: 'bearer' })
        .send(employmentDetails)
        .expect(200)
        .expect((res) => {
          expect(res.body.employmentStatus).toBe(
            employmentDetails.employmentStatus,
          );
          expect(res.body.companyName).toBe(employmentDetails.companyName);
          expect(res.body.employmentDetailsProvided).toBe(true);
          expect(res.body.kycCompletionPercentage).toBeGreaterThan(0);
        });
    });
  });

  describe('Bank Details', () => {
    it('should update bank details: /api/v1/kyc/update-bank-details (PATCH)', async () => {
      const bankDetails = {
        bankName: 'Test Bank',
        accountNumber: '1234567890',
      };
      (SmileService.prototype.verifyBankAccount as jest.Mock).mockResolvedValue(
        true,
      );

      return request(app)
        .patch('/api/v1/kyc/update-bank-details')
        .auth(userToken, { type: 'bearer' })
        .send(bankDetails)
        .expect(200)
        .expect((res) => {
          expect(res.body.bankName).toBe(bankDetails.bankName);
          expect(res.body.accountNumber).toBe(bankDetails.accountNumber);
          expect(res.body.bankDetailsProvided).toBe(true);
          expect(res.body.kycCompletionPercentage).toBeGreaterThan(0);
        });
    });
  });

  describe('Next of Kin Details', () => {
    it('should update next of kin details: /api/v1/kyc/update-nextOfkin-details (PATCH)', async () => {
      const nextOfKinDetails = {
        nextOfKinFirstname: 'John',
        nextOfKinMiddlename: 'Doe',
        nextOfKinGender: 'Male',
        nextOfKinEmail: 'john.doe@example.com',
        nextOfKinPhone: '1234567890',
        nextofkinRelationship: 'Sibling',
      };

      return request(app)
        .patch('/api/v1/kyc/update-nextOfkin-details')
        .auth(userToken, { type: 'bearer' })
        .send(nextOfKinDetails)
        .expect(200)
        .expect((res) => {
          expect(res.body.nextOfKinFirstname).toBe(
            nextOfKinDetails.nextOfKinFirstname,
          );
          expect(res.body.nextOfKinEmail).toBe(nextOfKinDetails.nextOfKinEmail);
          expect(res.body.nextOfKinDetailsProvided).toBe(true);
          expect(res.body.kycCompletionPercentage).toBeGreaterThan(0);
        });
    });
  });

  describe('Address Proof', () => {
    it('should upload address proof: /api/v1/kyc/update-nextOfkin-details (PATCH)', async () => {
      const mockFile = {
        buffer: Buffer.from('mock-file'),
        originalname: 'address_proof.pdf',
      };
      const addressProofDetails = {
        documentType: 'Utility Bill',
      };
      (FilesS3Service.prototype.create as jest.Mock).mockResolvedValue({
        file: { path: 'mock-path' },
      });
      (
        SmileService.prototype.verifyAddressProof as jest.Mock
      ).mockResolvedValue(true);

      return request(app)
        .patch('/api/v1/kyc/update-nextOfkin-details')
        .auth(userToken, { type: 'bearer' })
        .field('documentType', addressProofDetails.documentType)
        .attach('addressProof', mockFile.buffer, mockFile.originalname)
        .expect(200)
        .expect((res) => {
          expect(res.body.addressProofPath).toBe('mock-path');
          expect(res.body.addressProofProvided).toBe(true);
          expect(res.body.kycCompletionPercentage).toBeGreaterThan(0);
        });
    });
  });

  describe('KYC Progress', () => {
    it('should get KYC progress: /api/v1/kyc/progress (GET)', async () => {
      return request(app)
        .get('/api/v1/kyc/progress')
        .auth(userToken, { type: 'bearer' })
        .expect(200)
        .expect((res) => {
          expect(res.body.percentage).toBeDefined();
          expect(res.body.completedSteps).toBeInstanceOf(Array);
        });
    });
  });
});
