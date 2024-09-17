import {
  Injectable,
  HttpStatus,
  UnprocessableEntityException,
  NotFoundException,
  UnauthorizedException,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { randomStringGenerator } from '@nestjs/common/utils/random-string-generator.util';
import ms from 'ms';

import { UserEntity } from '../users/infrastructure/persistence/relational/entities/user.entity';
import { AuthOtpEntity } from '../users/infrastructure/persistence/relational/entities/authOtp.entity';
import { UserService } from '../users/users.service';
import { SessionService } from '../session/session.service';

import { NotificationsService } from '../notifications/notifications.service';
import { AuthProvidersEnum } from './auth-providers.enum';

import { StatusEnum } from '../statuses/statuses.enum';
import { User } from '../users/domain/user';

import { LoginResponseDto } from './dto/login-response.dto';

import { Session } from '../session/domain/session';
import { JwtPayloadType } from './strategies/types/jwt-payload.type';
import { JwtRefreshPayloadType } from './strategies/types/jwt-refresh-payload.type';
import { AuthEmailLoginDto } from './dto/auth-email-login.dto';
import { AuthRegisterDto } from './dto/auth-register-login.dto';
import { AuthConfirmEmailDto } from './dto/auth-confirm-email.dto';
import { AuthUpdateDto } from './dto/auth-update.dto';
import { RoleEnum } from '../roles/roles.enum';
import { AuthresendOtpDto } from './dto/resendOtp.dto';
import { AuthForgotPasswordDto } from './dto/auth-forgot-password.dto';
import { AuthResetPasswordDto } from './dto/auth-reset-password.dto';
import { Mailer } from '../mail/mail.service';
import { WalletEntity } from '../users/infrastructure/persistence/relational/entities/wallet.entity';

@Injectable()
export class AuthService {

  private readonly logger = new Logger(AuthService.name);
  constructor(
    private jwtService: JwtService,
    @InjectRepository(UserEntity)
    private readonly usersRepository: Repository<UserEntity>,
    @InjectRepository(AuthOtpEntity)
    private readonly authOtpRepository: Repository<AuthOtpEntity>,
    @InjectRepository(WalletEntity)
    private readonly walletRepository:Repository<WalletEntity>,
    private usersService: UserService,
    private sessionService: SessionService,
    private mailService: Mailer,
    private  notificationsService: NotificationsService,
    private configService: ConfigService,
  ) {}

  async validateLogin(loginDto: AuthEmailLoginDto): Promise<LoginResponseDto> {
    try {
      this.logger.log(`Attempting to validate login for email: ${loginDto.email}`);
      const user = await this.usersRepository.findOne({where:{email:loginDto.email}});
      if (!user) {
        this.logger.warn(`Login failed: User not found for email: ${loginDto.email}`);
        throw new UnprocessableEntityException({
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: { email: 'notFound' },
        });
      }

      this.validateUserForLogin(user);
      await this.comparePassword(loginDto.password, user.password);

      const session = await this.createSession(user);
      const tokens = await this.getTokensData({
        id: user.id,
        role: user.role,
        sessionId: session.id,
        hash: session.hash,
      });

      this.logger.log(`Login successful for user: ${user.id}`);
      return { ...tokens, user };
    } catch (error) {
      this.logger.error(`Login failed: ${error.message}`, error.stack);
      throw error;
    }
  }



   private validateUserForLogin(user: User): void {
    if (user.provider !== AuthProvidersEnum.email) {
      this.logger.warn(`Login failed: User ${user.id} needs to login via provider: ${user.provider}`);
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { email: `needLoginViaProvider:${user.provider}` },
      });
    }

    if (!user.isVerified) {
      this.logger.warn(`Login failed: User ${user.id} is not verified`);
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { email: 'userNotVerified' },
      });
    }
  }




  private async comparePassword(userPassword, dbPassword): Promise<boolean> {
    try {
      const isMatch = await bcrypt.compare(userPassword, dbPassword);
      if (!isMatch) {
        this.logger.warn('Login failed: Password mismatch');
      }
      return isMatch;
    } catch (error) {
      this.logger.error(`Password comparison failed: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Error during password comparison');
    }
  }



  private async createSession(user: User) {
    try {
      const hash = crypto
        .createHash('sha256')
        .update(randomStringGenerator())
        .digest('hex');

      this.logger.log(`Creating new session for user: ${user.id}`);
      return this.sessionService.create({ user, hash });
    } catch (error) {
      this.logger.error(`Session creation failed: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Error creating session');
    }
  }
  async register(dto: AuthRegisterDto): Promise<{ user: UserEntity }> {
    try {
      this.logger.log(`Attempting to register new user with email: ${dto.email}`);
      const age = this.calculateAge(dto.DOB);
      if (age < 18) {
        this.logger.warn(`Registration failed: User age (${age}) is below approved age`);
        throw new UnprocessableEntityException({
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          error: { age: 'ageBelowApprovedAge' },
        });
      }

      await this.checkExistingEmail(dto.email);

      const password = await this.hashPassword(dto.password);
      const user = await this.createUser({ ...dto, age, password });

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const now = new Date();
      const oneminutelater = new Date(now.getTime() + 60000);
      const tenminuteslater = new Date(now.getTime() + 600000);

      await this.authOtpRepository.save(
        this.authOtpRepository.create({
          otp: otp,
          email: user.email,
          verified: false,
          expiration_time: tenminuteslater,
          resend_time: oneminutelater,
          role: RoleEnum.USER,
        }),
      );

      await this.mailService.SendVerificationeMail(user.email, otp);

      await this.notificationsService.create({
        message: `Welcome ${user.firstName}, your account has been created successfully.`,
        subject: 'Account Creation',
        account: user.id,
      });

      this.logger.log(`User successfully registered: ${user.id}`);
      return { user };
    } catch (error) {
      this.logger.error(`Registration failed: ${error.message}`, error.stack);
      throw error;
    }
  }

  private calculateAge(dob: string): number {
    const birthDate = new Date(dob);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    if (
      monthDiff < 0 ||
      (monthDiff === 0 && today.getDate() < birthDate.getDate())
    ) {
      age--;
    }
    return age;
  }

  private async checkExistingEmail(email: string): Promise<void> {
    const existingUser = await this.usersRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { email: 'emailAlreadyExists' },
      });
    }
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, await bcrypt.genSalt());
  }

  private async createUser(userData: Partial<UserEntity>): Promise<UserEntity> {
    const userPayload = {
      ...userData,
      role: RoleEnum.USER,
      status: StatusEnum.ACTIVE,
      provider: AuthProvidersEnum.email,
    };
    return this.usersRepository.save(this.usersRepository.create(userPayload));
  }

  async confirmEmail(dto: AuthConfirmEmailDto): Promise<void> {
    try {
      const otpRecord = await this.verifyOtp(dto.otp);
      const user = await this.getUserForEmailConfirmation(otpRecord.email);

      await this.updateUserAfterConfirmation(user);
      await this.markOtpAsVerified(otpRecord);
      await this.mailService.WelcomeMail(user.email, user.firstName);
      await this.createVerificationNotification(user);

      // Create a wallet for the user
      await this.walletRepository.save(this.walletRepository.create({
        balance: 0,
        createdAt: new Date(),
        owner: user
      }));
    } catch (error) {
      this.logger.error(`Something went wrong during email confirmation`, error.stack);
      throw error;
    }
  }

  private async verifyOtp(otp: string): Promise<AuthOtpEntity> {
    const otpRecord = await this.authOtpRepository.findOne({
      where: { otp:otp },
    });
    if (!otpRecord) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { otp: 'invalidOtp' },
      });
    }

    const currentTime = new Date();
    if (otpRecord.expiration_time < currentTime) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { otp: 'otpExpired' },
      });
    }

    return otpRecord;
  }

  private async getUserForEmailConfirmation(email: string): Promise<UserEntity> {
    const user = await this.usersRepository.findOne({where:{email:email}});
    if (!user ) {
      throw new NotFoundException({
        status: HttpStatus.NOT_FOUND,
        error: 'notFound',
      });
    }
    return user;
  }

  private async updateUserAfterConfirmation(user: User): Promise<void> {
    user.status = StatusEnum.ACTIVE;
    user.isVerified = true;
    user.kycCompletionStatus = {
      ...user.kycCompletionStatus,
      userRegisteredAndVerified: true,
    };
    await this.usersService.update(user.id, user);
  }

  private async markOtpAsVerified(otpRecord: AuthOtpEntity): Promise<void> {
    otpRecord.verified = true;
    await this.authOtpRepository.save(otpRecord);
  }

  private async createVerificationNotification(user: User): Promise<void> {
    await this.notificationsService.create({
      message: `Hi ${user.firstName}, your account has been verified successfully.`,
      subject: 'Account Verification',
      account: user.id,
    });
  }




  async resendOtpAfterRegistration(dto: AuthresendOtpDto): Promise<any> {
   try {
     const existingOtp = await this.authOtpRepository.findOne({
       where: { email: dto.email },
     });
 
     const user = await this.usersService.findByEmail(dto.email);
 
     if (!existingOtp) {
       throw new UnprocessableEntityException({
         status: HttpStatus.UNPROCESSABLE_ENTITY,
         error: 'No OTP found for this email',
       });
     }
 
     const now = new Date();
     if (now < existingOtp.resend_time) {
       throw new UnprocessableEntityException({
         status: HttpStatus.UNPROCESSABLE_ENTITY,
         error: 'Please wait before requesting a new OTP',
       });
     }
 
     // Generate new OTP
     const newOtp = Math.floor(100000 + Math.random() * 900000).toString();
 
     // Update timestamps
     const oneminutelater = new Date(now.getTime() + 1 * 60000);
     const tenminuteslater = new Date(now.getTime() + 10 * 60000);
 
     // Update OTP record
     await this.authOtpRepository.update(existingOtp.id, {
       otp: newOtp,
       verified: false,
       expiration_time: tenminuteslater,
       resend_time: oneminutelater,
     });
 
     // Send new OTP via email
     await this.mailService.SendVerificationeMail(dto.email, newOtp);
     return {message:'new otp sent successfully'}
   } catch (error) {
    throw error
    
   }
  }

  async resendExpiredOtp(dto: AuthresendOtpDto): Promise<any> {
    try {
      const existingOtp = await this.authOtpRepository.findOne({
        where: { email: dto.email },
      });
  
      if (!existingOtp) {
        throw new UnprocessableEntityException({
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          error: 'No OTP found for this email',
        });
      }
  
      const now = new Date();
      if (now < existingOtp.expiration_time) {
        throw new UnprocessableEntityException({
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          error: 'Current OTP has not expired yet',
        });
      }
  
      // Generate new OTP
      const newOtp = Math.floor(100000 + Math.random() * 900000).toString();
  
      // Update timestamps
      const tenminuteslater = new Date(now.getTime() + 10 * 60000);
  
      // Update OTP record
      await this.authOtpRepository.update(existingOtp.id, {
        otp: newOtp,
        verified: false,
        expiration_time: tenminuteslater,
        resend_time: now, // Reset resend_time to now
      });
  
      // Send new OTP via email
      await this.mailService.SendVerificationeMail(dto.email, newOtp);

      return {message:'new otp sent successfully'}
    } catch (error) {
      throw error
      
    }
  }



  async forgotPassword(dto: AuthForgotPasswordDto): Promise<any> {
try {
      const user = await this.usersService.findByEmail(dto.email);
  
      if (!user) {
        throw new UnprocessableEntityException({
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            email: 'emailNotExists',
          },
        });
      }
  
      const tokenExpiresIn = this.configService.getOrThrow('auth.forgotExpires', {
        infer: true,
      });
  
      const tokenExpires = Date.now() + ms(tokenExpiresIn);
  
      const hash = await this.jwtService.signAsync(
        {
          forgotUserId: user.id,
        },
        {
          secret: this.configService.getOrThrow('auth.forgotSecret', {
            infer: true,
          }),
          expiresIn: tokenExpiresIn,
        },
      );
  
      await this.mailService.SendPasswordResetLinkMail(
        dto.email,
        hash,
        user.firstName,
  
      );
      return {messge:'password reset link sent successfully'}
} catch (error) {
  throw error 
  
}

  }

  async resetPassword(dto: AuthResetPasswordDto): Promise<any> {
   try {
     const user = await this.usersService.findByEmail(dto.email);
     try {
       const jwtData = await this.jwtService.verifyAsync<{
         forgotUserId: User['id'];
       }>(dto.hash, {
         secret: this.configService.getOrThrow('auth.forgotSecret', {
           infer: true,
         }),
       });
 
       //user = jwtData.forgotUserId;
     } catch {
      
       throw new UnprocessableEntityException({
         status: HttpStatus.UNPROCESSABLE_ENTITY,
         errors: {
           hash: `invalidHash`,
         },
       });
     }
 
     //const user = await this.usersService.findById(userId);
 
     if (!user) {
       throw new UnprocessableEntityException({
         status: HttpStatus.UNPROCESSABLE_ENTITY,
         errors: {
           hash: `notFound`,
         },
       });
     }
 
     // Hash the password before saving the user
     const hashedPassword = dto.password
       ? await bcrypt.hash(dto.password, await bcrypt.genSalt())
       : undefined;
 
     user.password = hashedPassword;
 
     await this.sessionService.deleteByUserId({
       userId: user.id,
     });
 
     await this.usersService.update(user.id, user);


     await this.notificationsService.create({
      message: ` ${user.firstName}, you have  successfully performed a password reset.`,
      subject: 'Password Reset',
      account: user.id,
    });
    

    this.logger.log(`User successfully Reset Password: ${user.id}`);

    return {message:'password reset successful'}

   } catch (error) {
    this.logger.error(`Reset Password failed: ${error.message}`, error.stack);
    throw error;
    
   }
  }

   async me(user:UserEntity) {
    try {
      this.logger.log(`Fetching user data for user: ${user.id}`);
      const userProfile = await this.usersRepository.findOne({where:{id:user.id},relations:['my_cards','my_transactions','my_wallet']});
      if (!user) throw new UnprocessableEntityException({
        error:'userNotFound',
        status:HttpStatus.UNPROCESSABLE_ENTITY
      })
      return userProfile
    } catch (error) {
      this.logger.error(`Error fetching user data: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Error fetching user data');
    }
  }



  async update(
    userJwtPayload: JwtPayloadType,
    userDto: AuthUpdateDto,
  ): Promise<any> {
    try {
      this.logger.log(`Attempting to update user: ${userJwtPayload.id}`);
      const currentUser = await this.usersService.findById(userJwtPayload.id);
      if (!currentUser) {
        this.logger.warn(`Update failed: User not found for id: ${userJwtPayload.id}`);
        throw new UnprocessableEntityException({
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: { user: 'userNotFound' },
        });
      }

      if (userDto.password) {
        await this.handlePasswordUpdate(currentUser, userDto, userJwtPayload);
      }

      if (userDto.email && userDto.email !== currentUser.email) {
        this.logger.log(`Updating email for user: ${userJwtPayload.id}`);
        currentUser.email = userDto.email;

        delete userDto.email;
        delete userDto.oldPassword;

        await this.usersRepository.save(currentUser);
        return this.usersService.findById(userJwtPayload.id);
      }
    } catch (error) {
      this.logger.error(`Update failed: ${error.message}`, error.stack);
      throw error;
    }
  }

  private async handlePasswordUpdate(
    currentUser: User,
    userDto: AuthUpdateDto,
    userJwtPayload: JwtPayloadType,
  ): Promise<void> {
    if (!userDto.oldPassword) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { oldPassword: 'missingOldPassword' },
      });
    }

    const isValidOldPassword = await this.comparePassword(
      userDto.oldPassword,
      currentUser.password,
    );
    if (!isValidOldPassword) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { oldPassword: 'incorrectOldPassword' },
      });
    }

    await this.sessionService.deleteByUserIdWithExclude({
      userId: currentUser.id,
      excludeSessionId: userJwtPayload.sessionId,
    });
  }



  async refreshToken(
    data: Pick<JwtRefreshPayloadType, 'sessionId' | 'hash'>,
  ): Promise<Omit<LoginResponseDto, 'user'>> {
    try {
      this.logger.log(`Attempting to refresh token for session: ${data.sessionId}`);
      const session = await this.sessionService.findById(data.sessionId);
      if (!session || session.hash !== data.hash) {
        this.logger.warn(`Token refresh failed: Invalid session or hash for session: ${data.sessionId}`);
        throw new UnauthorizedException();
      }

      const user = await this.usersService.findById(session.user.id);
      if (!user?.role) {
        this.logger.warn(`Token refresh failed: User not found or no role for user: ${session.user.id}`);
        throw new UnauthorizedException();
      }

      const hash = crypto
        .createHash('sha256')
        .update(randomStringGenerator())
        .digest('hex');
      await this.sessionService.update(session.id, { hash });

      this.logger.log(`Token refreshed successfully for user: ${user.id}`);
      return this.getTokensData({
        id: session.user.id,
        role: user.role,
        sessionId: session.id,
        hash,
      });
    } catch (error) {
      this.logger.error(`Token refresh failed: ${error.message}`, error.stack);
      throw error;
    }
  }





   async softDelete(user: User): Promise<void> {
    try {
      this.logger.log(`Soft deleting user: ${user.id}`);
      await this.usersService.remove(user.id);
    } catch (error) {
      this.logger.error(`Soft delete failed: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Error during soft delete');
    }
  }



  async logout(data: Pick<JwtRefreshPayloadType, 'sessionId'>): Promise<void> {
    try {
      this.logger.log(`Logging out session: ${data.sessionId}`);
      await this.sessionService.deleteById(data.sessionId);
    } catch (error) {
      this.logger.error(`Logout failed: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Error during logout');
    }
  }

   private async getTokensData(data: {
    id: User['id'];
    role: User['role'];
    sessionId: Session['id'];
    hash: Session['hash'];
  }): Promise<Omit<LoginResponseDto, 'user'>> {
    try {
      this.logger.log(`Generating tokens for user: ${data.id}`);
      const tokenExpiresIn = this.configService.get('auth.expires');
      const tokenExpiresInMs =
        typeof tokenExpiresIn === 'string' ? ms(tokenExpiresIn) : tokenExpiresIn;
      const tokenExpires =
        Date.now() +
        (typeof tokenExpiresInMs === 'number' ? tokenExpiresInMs : 0);

      const [token, refreshToken] = await Promise.all([
        this.jwtService.signAsync(
          { id: data.id, role: data.role, sessionId: data.sessionId },
          {
            secret: this.configService.get('auth.secret'),
            expiresIn: tokenExpiresIn,
          },
        ),
        this.jwtService.signAsync(
          { sessionId: data.sessionId, hash: data.hash },
          {
            secret: this.configService.get('auth.refreshSecret'),
            expiresIn: this.configService.get('auth.refreshExpires'),
          },
        ),
      ]);

      return { token, refreshToken, tokenExpires };
    } catch (error) {
      this.logger.error(`Token generation failed: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Error generating tokens');
    }
  }
}
 