// import { Injectable } from '@nestjs/common';
// import { ConfigService } from '@nestjs/config';
// import { I18nContext } from 'nestjs-i18n';
// import { MailData } from './interfaces/mail-data.interface';

// import { MaybeType } from '../utils/types/maybe.type';
// import { MailerService } from '../mailer/mailer.service';
// import path from 'path';
// import { AllConfigType } from '../config/config.type';

// @Injectable()
// export class MailService {
//   constructor(
//     private readonly mailerService: MailerService,
//     private readonly configService: ConfigService<AllConfigType>,
//   ) {}

//   async userSignUp(mailData: MailData<{ otp: string }>): Promise<void> {
//     const i18n = I18nContext.current();
//     let emailConfirmTitle: MaybeType<string>;
//     let text1: MaybeType<string>;
//     let text2: MaybeType<string>;
//     let text3: MaybeType<string>;

//     if (i18n) {
//       [emailConfirmTitle, text1, text2, text3] = await Promise.all([
//         i18n.t('common.confirmEmail'),
//         i18n.t('confirm-email.text1'),
//         i18n.t('confirm-email.text2'),
//         i18n.t('confirm-email.text3'),
//       ]);
//     }

//     // Generate a 6-digit OTP (or receive it from the calling function)
//     const otp = mailData.data.otp; // OTP should be generated before calling this function

//     // Send OTP via email
//     await this.mailerService.sendMail({
//       to: mailData.to,
//       subject: emailConfirmTitle, // You can customize the subject
//       text: `${emailConfirmTitle}: ${otp}`, // Send OTP in plain text
//       templatePath: path.join(
//         this.configService.getOrThrow('app.workingDirectory', { infer: true }),
//         'src',
//         'mail',
//         'mail-templates',
//         'otp-activation.hbs', // You may want to create a new OTP-specific template
//       ),
//       context: {
//         title: emailConfirmTitle,
//         otp, // Include OTP in the template context
//         app_name: this.configService.get('app.name', { infer: true }),
//         text1,
//         text2,
//         text3,
//       },
//     });
// }




//   async forgotPassword(
//     mailData: MailData<{ hash: string; tokenExpires: number }>,
//   ): Promise<void> {
//     const i18n = I18nContext.current();
//     let resetPasswordTitle: MaybeType<string>;
//     let text1: MaybeType<string>;
//     let text2: MaybeType<string>;
//     let text3: MaybeType<string>;
//     let text4: MaybeType<string>;

//     if (i18n) {
//       [resetPasswordTitle, text1, text2, text3, text4] = await Promise.all([
//         i18n.t('common.resetPassword'),
//         i18n.t('reset-password.text1'),
//         i18n.t('reset-password.text2'),
//         i18n.t('reset-password.text3'),
//         i18n.t('reset-password.text4'),
//       ]);
//     }

//     const url = new URL(
//       this.configService.getOrThrow('app.frontendDomain', {
//         infer: true,
//       }) + '/password-change',
//     );
//     url.searchParams.set('hash', mailData.data.hash);
//     url.searchParams.set('expires', mailData.data.tokenExpires.toString());

//     await this.mailerService.sendMail({
//       to: mailData.to,
//       subject: resetPasswordTitle,
//       text: `${url.toString()} ${resetPasswordTitle}`,
//       templatePath: path.join(
//         this.configService.getOrThrow('app.workingDirectory', {
//           infer: true,
//         }),
//         'src',
//         'mail',
//         'mail-templates',
//         'reset-password.hbs',
//       ),
//       context: {
//         title: resetPasswordTitle,
//         url: url.toString(),
//         actionTitle: resetPasswordTitle,
//         app_name: this.configService.get('app.name', {
//           infer: true,
//         }),
//         text1,
//         text2,
//         text3,
//         text4,
//       },
//     });
//   }

//   async confirmNewEmail(mailData: MailData<{ hash: string }>): Promise<void> {
//     const i18n = I18nContext.current();
//     let emailConfirmTitle: MaybeType<string>;
//     let text1: MaybeType<string>;
//     let text2: MaybeType<string>;
//     let text3: MaybeType<string>;

//     if (i18n) {
//       [emailConfirmTitle, text1, text2, text3] = await Promise.all([
//         i18n.t('common.confirmEmail'),
//         i18n.t('confirm-new-email.text1'),
//         i18n.t('confirm-new-email.text2'),
//         i18n.t('confirm-new-email.text3'),
//       ]);
//     }

//     const url = new URL(
//       this.configService.getOrThrow('app.frontendDomain', {
//         infer: true,
//       }) + '/confirm-new-email',
//     );
//     url.searchParams.set('hash', mailData.data.hash);

//     await this.mailerService.sendMail({
//       to: mailData.to,
//       subject: emailConfirmTitle,
//       text: `${url.toString()} ${emailConfirmTitle}`,
//       templatePath: path.join(
//         this.configService.getOrThrow('app.workingDirectory', {
//           infer: true,
//         }),
//         'src',
//         'mail',
//         'mail-templates',
//         'confirm-new-email.hbs',
//       ),
//       context: {
//         title: emailConfirmTitle,
//         url: url.toString(),
//         actionTitle: emailConfirmTitle,
//         app_name: this.configService.get('app.name', { infer: true }),
//         text1,
//         text2,
//         text3,
//       },
//     });
//   }

  
//   async welcomeMail(mailData: MailData): Promise<void> {
//     const i18n = I18nContext.current();
    
//     let welcomeTitle: MaybeType<string>;
//     let welcomeText1: MaybeType<string>;
//     let welcomeText2: MaybeType<string>;
//     let welcomeText3: MaybeType<string>;
  
//     if (i18n) {
//       [welcomeTitle, welcomeText1, welcomeText2, welcomeText3] = await Promise.all([
//         i18n.t('common.welcomeTitle'),
//         i18n.t('welcome-email.text1'),
//         i18n.t('welcome-email.text2'),
//         i18n.t('welcome-email.text3'),
//       ]);
//     }
  
//     // Send welcome email
//     await this.mailerService.sendMail({
//       to: mailData.to,
//       subject: welcomeTitle || 'Welcome to Our Platform',
//       text: `${welcomeText1 || 'We are excited to have you on board!'}`,
//       templatePath: path.join(
//         this.configService.getOrThrow('app.workingDirectory', { infer: true }),
//         'src',
//         'mail',
//         'mail-templates',
//         'welcome.hbs',  // Template for the welcome email
//       ),
//       context: {
//         title: welcomeTitle || 'Welcome to Our Platform',
//         app_name: this.configService.get('app.name', { infer: true }),
//         text1: welcomeText1,
//         text2: welcomeText2,
//         text3: welcomeText3,
//         actionTitle: 'Get Started',
        
//       },
//     });
//   }
  

// }


//welcome

// otp for 2fa

// reset password token

// confirmation of other and sending tracking number

// when an order is completed
import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class Mailer {
  constructor(private readonly mailerservice: MailerService) {}

  async SendVerificationeMail(
    email: string,
    //name: string,
    otpCode:string
   
  ): Promise<void> {
    const subject = 'Email Verification Mail';
    const content = `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Verification - Verification Linke</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
            color: #333333;
            line-height: 1.6;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #ffffff;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
          }
          .logo {
            text-align: center;
            margin-bottom: 10px;
          }
          .verification-heading {
            text-align: center;
            color: #53B1FD;
            font-size: 24px;
            margin-bottom: 10px;
          }
          .message {
            text-align: center;
            font-size: 16px;
            margin-bottom: 20px;
          }
          .otp {
            text-align: center;
            font-size: 30px;
            color: #53B1FD;
            font-weight: bold;
            margin-bottom: 20px;
          }
          .instructions {
            font-size: 16px;
            line-height: 1.4;
            margin-bottom: 20px;
          }
          .footer {
            text-align: center;
            margin-top: 20px;
            color: #777777;
          }
          .social-icons {
            margin-top: 10px;
          }
          .social-icons img {
            width: 30px;
            margin: 0 5px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">
            
          </div>
          <h1 class="verification-heading">Hi,</h1>
          <p class="message">Your one-time password (OTP) for verification is:</p>
          <p class="otp">${otpCode}</p>
          <p class="message">If you did not request this OTP, please ignore this email.</p>
          <div class="footer">
            <p>Ostra Logistics</p>
            <div class="social-icons">
              <a href="https://facebook.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/facebook-new.png" alt="Facebook"></a>
              <a href="https://twitter.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/twitter.png" alt="Twitter"></a>
              <a href="https://instagram.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/instagram-new.png" alt="Instagram"></a>
              <a href="https://tiktok.com/@ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/tiktok.png" alt="TikTok"></a>
            </div>
          </div>
        </div>
      </body>
    </html>`;
    await this.mailerservice.sendMail({ to: email, subject, html: content });
  }
  



  async SendPasswordResetLinkMail(
    email: string,
    resettoken: string,
    name: string,
  ): Promise<void> {
    const subject = 'Password Reset Request';
    const content = `<!DOCTYPE html>
      <html>
        <head>
          <title>Password Reset Request</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              background-color: #f2f2f2;
              color: #333333;
              line-height: 1.6;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              padding: 20px;
              background-color: #ffffff;
              border-radius: 10px;
              box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            .logo {
              text-align: center;
              margin-bottom: 10px;
            }
            .verification-heading {
              text-align: center;
              color: #53B1FD;
              font-size: 20px;
              margin-bottom: 10px;
            }
            .message {
              text-align: center;
              font-size: 16px;
              margin-bottom: 20px;
            }
            .instructions {
              font-size: 16px;
              line-height: 1.4;
            }
            .footer {
              text-align: center;
              margin-top: 20px;
              color: #777777;
            }
            .social-icons {
              margin-top: 10px;
            }
            .social-icons img {
              width: 30px;
              margin: 0 5px;
            }
            .reset-button {
              display: block;
              width: 200px;
              margin: 20px auto;
              padding: 10px 0;
              background-color: #53B1FD;
              color: white;
              text-align: center;
              text-decoration: none;
              border-radius: 5px;
              font-size: 16px;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="logo">
             
            </div>
            <h1 class="verification-heading">Password Reset Request</h1>
            <p class="message">Hi ${name},</p>
            <div class="instructions">
              <p>It seems like you requested to reset your password. Please click the button below to proceed with resetting your password:</p>
              <a href="${process.env.FRONTEND_URL}/reset-password?token=${resettoken}" class="reset-button">Reset Password</a>
              <p>If you did not request this, please ignore this email.</p>
            </div>
            <div class="footer">
              <p>Ostra Logistics</p>
              <div class="social-icons">
                <a href="https://facebook.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/facebook-new.png" alt="Facebook"></a>
                <a href="https://twitter.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/twitter.png" alt="Twitter"></a>
                <a href="https://instagram.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/instagram-new.png" alt="Instagram"></a>
                <a href="https://tiktok.com/@ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/tiktok.png" alt="TikTok"></a>
              </div>
            </div>
          </div>
        </body>
      </html>`;
    await this.mailerservice.sendMail({ to: email, subject, html: content });
  }
  
  


  async WelcomeMail(email: string, name: string): Promise<void> {
    const subject = 'Welcome To Ostra Logistics';
    const content = `<!DOCTYPE html>
      <html>
        <head>
          <title>Welcome to Ostra Logistics</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              background-color: #f2f2f2;
              color: #333333;
              line-height: 1.6;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              padding: 20px;
              background-color: #ffffff;
              border-radius: 10px;
              box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            .logo {
              text-align: center;
              margin-bottom: 10px;
            }
            .verification-heading {
              text-align: center;
              color: #53B1FD;
              font-size: 20px;
              margin-bottom: 10px;
            }
            .message {
              text-align: center;
              font-size: 16px;
              margin-bottom: 20px;
            }
            .instructions {
              font-size: 16px;
              line-height: 1.4;
            }
            .footer {
              text-align: center;
              margin-top: 20px;
              color: #777777;
            }
            .social-icons {
              margin-top: 10px;
            }
            .social-icons img {
              width: 30px;
              margin: 0 5px;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="logo">
              <img src="https://res.cloudinary.com/dma3njgsr/image/upload/v1720577913/oppc1paydigfmzkgdgc8.png" alt="Ostra Logistics">
            </div>
            <h1 class="verification-heading">Welcome OnBoard!</h1>
            <p class="message">Hi ${name},</p>
            <div class="instructions">
              <p>We are thrilled to have you join our platform. With Ostra Logistics, you can easily manage your deliveries, track orders in real-time, and more.</p>
              <p>If you have any questions or need assistance, feel free to reach out to our support team.</p>
              <p>Happy delivering!</p>
              <p>For any questions or assistance, contact our support team at <a href="mailto:ostralogistics@gmail.com">support@ostralogistics.com</a></p>
            </div>
            <div class="footer">
              <p>Ostra Logistics</p>
              <div class="social-icons">
                <a href="https://facebook.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/facebook-new.png" alt="Facebook"></a>
                <a href="https://twitter.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/twitter.png" alt="Twitter"></a>
                <a href="https://instagram.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/instagram-new.png" alt="Instagram"></a>
                <a href="https://tiktok.com/@ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/tiktok.png" alt="TikTok"></a>
              </div>
            </div>
          </div>
        </body>
      </html>`;
    await this.mailerservice.sendMail({ to: email, subject, html: content });
  }


  async sendFundingConfirmation(email: string, amount: number): Promise<void> {
    const subject = 'Account Funding Confirmation';
    const content = `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Account Funding Confirmation</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background-color: #f2f2f2;
          color: #333333;
          line-height: 1.6;
          margin: 0;
          padding: 0;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
          background-color: #ffffff;
          border-radius: 10px;
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .logo {
          text-align: center;
          margin-bottom: 10px;
        }
        .heading {
          text-align: center;
          color: #53B1FD;
          font-size: 24px;
          margin-bottom: 10px;
        }
        .message {
          text-align: center;
          font-size: 16px;
          margin-bottom: 20px;
        }
        .amount {
          text-align: center;
          font-size: 30px;
          color: #53B1FD;
          font-weight: bold;
          margin-bottom: 20px;
        }
        .footer {
          text-align: center;
          margin-top: 20px;
          color: #777777;
        }
        .social-icons {
          margin-top: 10px;
        }
        .social-icons img {
          width: 30px;
          margin: 0 5px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">
          <!-- Add your logo here -->
        </div>
        <h1 class="heading">Account Funding Confirmation</h1>
        <p class="message">Your account has been successfully funded with:</p>
        <p class="amount">NGN ${amount}</p>
        <p class="message">Thank you for using our service. If you did not initiate this transaction, please contact our support team immediately.</p>
        <div class="footer">
          <p>Ostra Logistics</p>
          <div class="social-icons">
            <a href="https://facebook.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/facebook-new.png" alt="Facebook"></a>
            <a href="https://twitter.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/twitter.png" alt="Twitter"></a>
            <a href="https://instagram.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/instagram-new.png" alt="Instagram"></a>
            <a href="https://tiktok.com/@ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/tiktok.png" alt="TikTok"></a>
          </div>
        </div>
      </div>
    </body>
    </html>
    `;
    await this.mailerservice.sendMail({ to: email, subject, html: content });
  }



  async sendCardAddedNotification(email: string, cardType:string,last4Digits:string,expiryMonth:string,expiryYear:string): Promise<void> {
    const subject = 'New Card Added';
    const content = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>New Card Added</title>
  <style>
    /* Same style as the previous email */
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <!-- Add your logo here -->
    </div>
    <h1 class="heading">New Card Added</h1>
    <p class="message">A new card has been successfully added to your account.</p>
    <p class="message">Card Details:</p>
    <p class="message">
      Card Type: ${cardType}<br>
      Last 4 Digits: ${last4Digits}<br>
      Expiry: ${expiryMonth}/${expiryYear}
    </p>
    <p class="message">If you did not add this card, please contact our support team immediately.</p>
    <div class="footer">
      <p>Ostra Logistics</p>
      <div class="social-icons">
      <a href="https://facebook.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/facebook-new.png" alt="Facebook"></a>
      <a href="https://twitter.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/twitter.png" alt="Twitter"></a>
      <a href="https://instagram.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/instagram-new.png" alt="Instagram"></a>
      <a href="https://tiktok.com/@ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/tiktok.png" alt="TikTok"></a>
    </div>
    </div>
  </div>
</body>
</html>
    `;
    await this.mailerservice.sendMail({ to: email, subject, html: content });
  }

  async sendCardRemovedNotification(email: string, cardType:string, last4Digits:string): Promise<void> {
    const subject = 'Card Removed';
    const content = `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Card Removed</title>
      <style>
        /* Same style as the previous emails */
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">
          <!-- Add your logo here -->
        </div>
        <h1 class="heading">Card Removed</h1>
        <p class="message">A card has been removed from your account.</p>
        <p class="message">Card Details:</p>
        <p class="message">
          Card Type: ${cardType}<br>
          Last 4 Digits: ${last4Digits}
        </p>
        <p class="message">If you did not remove this card, please contact our support team immediately.</p>
        <div class="footer">
          <p>Ostra Logistics</p>
          <div class="social-icons">
          <a href="https://facebook.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/facebook-new.png" alt="Facebook"></a>
          <a href="https://twitter.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/twitter.png" alt="Twitter"></a>
          <a href="https://instagram.com/ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/instagram-new.png" alt="Instagram"></a>
          <a href="https://tiktok.com/@ostralogistics"><img src="https://img.icons8.com/fluent/48/000000/tiktok.png" alt="TikTok"></a>
        </div>
        </div>
      </div>
    </body>
    </html>
    `;
    await this.mailerservice.sendMail({ to: email, subject, html: content });
  }

  async sendWithdrawalConfirmation(email: string, amount: number): Promise<void> {
    const subject = 'Withdrawal Confirmation';
    const content = `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Withdrawal Confirmation</title>
      <style>
        /* Same style as the previous emails */
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">
          <!-- Add your logo here -->
        </div>
        <h1 class="heading">Withdrawal Confirmation</h1>
        <p class="message">A withdrawal has been processed from your account:</p>
        <p class="amount">NGN ${amount}</p>
        <p class="message">The funds have been sent to your registered bank account.</p>
        <p class="message">If you did not initiate this withdrawal, please contact our support team immediately.</p>
        <div class="footer">
          <p>Ostra Logistics</p>
          <div class="social-icons">
            <!-- Same social icons as the previous emails -->
          </div>
        </div>
      </div>
    </body>
    </html>
    `;
    await this.mailerservice.sendMail({ to: email, subject, html: content });
  }

  
  
}