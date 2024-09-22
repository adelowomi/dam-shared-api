import { Controller, Post, Body, Headers, Logger } from '@nestjs/common';
import { SmileService } from 'src/utils/services/smileID.service'; // Adjust the path as necessary
import { KycService } from '../kyc/user.kyc.service';
// Adjust the path as necessary

@Controller('webhooks')
export class WebhookController {
  private readonly logger = new Logger(WebhookController.name);

  constructor(
    private readonly kycService: KycService, // To update KYC status
    private readonly smileService: SmileService, // If any verification logic is needed
  ) {}

  @Post('smile-id')
  async handleSmileIdWebhook(
    @Body() payload: any,
    @Headers('Authorization') authorizationHeader: string,
  ): Promise<void> {
    try {
      // Validate the authorization header or signature (if required by SmileID)
      const isValid = this.smileService.verifyWebhook(
        authorizationHeader,
        payload,
      );

      if (!isValid) {
        this.logger.error('Invalid SmileID webhook signature');
        throw new Error('Invalid SmileID webhook signature');
      }

      // Process the webhook data (payload)
      this.logger.log('Received SmileID webhook data:', payload);

      const { job_id, result, partner_params } = payload;

      // Extract user ID from partner_params (assuming you passed user_id)
      const userId = partner_params?.user_id;

      if (result?.status === 'success') {
        // Update the KYC status in the database
        await this.kycService.UpdateKycStatus(userId);
        this.logger.log(`KYC verification successful for user ${userId}`);
      } else {
        // Handle KYC failure case
        this.logger.error(`KYC verification failed for user ${userId}`);
        await this.kycService.UpdateKycStatus(userId);
      }
    } catch (error) {
      this.logger.error('Error processing SmileID webhook', error.stack);
      throw new Error('Failed to process SmileID webhook');
    }
  }
}
