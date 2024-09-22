export class PayStackConfig {
  secretKey: string;
  publicKey: string;
  baseUrl: string;

  constructor(secretKey: string, publicKey: string, baseUrl: string) {
    this.secretKey = secretKey;
    this.publicKey = publicKey;
    this.baseUrl = baseUrl;
  }

  static fromEnv(): PayStackConfig {
    const secretKey = process.env.PAYSTACK_SECRET_KEY || '';
    const publicKey = process.env.PAYSTACK_PUBLIC_KEY || '';
    const baseUrl = process.env.PAYSTACK_BASE_URL || 'https://api.paystack.co';
    return new PayStackConfig(secretKey, publicKey, baseUrl);
  }
}
