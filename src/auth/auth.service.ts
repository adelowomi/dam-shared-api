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
import { ResponseService } from '../utils/services/response.service';

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
    private readonly walletRepository: Repository<WalletEntity>,
    private usersService: UserService,
    private sessionService: SessionService,
    private mailService: Mailer,
    private notificationsService: NotificationsService,
    private configService: ConfigService,
    private responseService: ResponseService,
  ) {}

  async validateLogin(loginDto: AuthEmailLoginDto): Promise<any> {
    try {
      this.logger.log(`Attempting to validate login for email: ${loginDto.email}`);
      const user = await this.usersRepository.findOne({where:{email:loginDto.email}});
      if (!user) {
        this.logger.warn(`Login failed: User not found for email: ${loginDto.email}`);
        return this.responseService.Response(
          false,
          'invalid credential',
          HttpStatus.NOT_FOUND,
          {},
        );
      }

      const comparepass = await this.comaprePassword(loginDto.password, user.password);
       if (!comparepass)
        return this.responseService.Response(
          false,
          'invalid credential',
          HttpStatus.NOT_FOUND,
          {}
        );
     
        if (!user.isVerified)
          return this.responseService.Response(
            false,
            'account not verified yet',
            HttpStatus.NOT_ACCEPTABLE,
            {},
          );

      const session = await this.createSession(user);
      const tokens = await this.getTokensData({
        id: user.id,
        role: user.role,
        sessionId: session.id,
        hash: session.hash,
      });

      this.logger.log(`Login successful for user: ${user.id}`);
      return this.responseService.Response(
        true,
        'login successful',
        HttpStatus.OK,
        {...tokens, user},
      );
    } catch (error) {
      this.logger.error(`Login failed: ${error.message}`, error.stack);
      throw error;
    }
  }

  private async comaprePassword(userpassword, dbpassword): Promise<boolean> {
    return await bcrypt.compare(userpassword, dbpassword);
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



  async register(dto: AuthRegisterDto): Promise<any> {
    try {
      this.logger.log(
        `Attempting to register new user with email: ${dto.email}`,
      );

      const existingUser = await this.usersRepository.findOne({
        where: { email:dto.email },
      });
      if (existingUser) {
        return this.responseService.Response(
          false,
          'email already exists',
          HttpStatus.UNPROCESSABLE_ENTITY,
          {},
        );
      }


      const age = this.calculateAge(dto.DOB);
      if (age < 18) {
        this.logger.warn(
          `Registration failed: User age (${age}) is below approved age`,
        );
        return this.responseService.Response(
          false,
          'age is below approved age, you must be 18 and above',
          HttpStatus.NOT_ACCEPTABLE,
          {},
        );
      }

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
      return this.responseService.Response(
        true,
        'user successfully registered',
        HttpStatus.CREATED,
        { user },
      );
    } catch (error) {
      this.logger.error(`Registration failed: ${error.message}`, error.stack);
      return this.responseService.Response(
        false,
        'something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { error: error },
      );
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

  async confirmEmail(dto: AuthConfirmEmailDto): Promise<any> {
    try {
      const findotp = await this.authOtpRepository.findOne({ where: { otp: dto.otp } });
      if (!findotp)
        return this.responseService.Response(
          false,
          'incorrect otp provided',
          HttpStatus.NOT_FOUND,
          {},
        );

      //find if the otp is expired
      if (findotp.expiration_time <= new Date())
        return this.responseService.Response(false, 'OTP is expired', HttpStatus.BAD_REQUEST,{});

      // Find the admin associated with the OTP
      const user = await this.usersRepository.findOne({
        where: { email: findotp.email },
      });
      if (!user)
        return this.responseService.Response(
          false,
          'no user is associated with this otp',
          HttpStatus.NOT_FOUND,
          {},
        );

      // Verify and update the customer's status
      user.isVerified = true;
      user.status = StatusEnum.ACTIVE;
      user.kycCompletionStatus = {
        ...user.kycCompletionStatus,
        userRegisteredAndVerified: true,
      };
      await this.usersRepository.save(user);

      findotp.verified = true;
      await this.authOtpRepository.save(findotp);
    

      await this.mailService.WelcomeMail(user.email, user.firstName);

      // Create a wallet for the user
      await this.walletRepository.save(
        this.walletRepository.create({
          balance: 0,
          createdAt: new Date(),
          owner: user,
        }),
      );

      await this.notificationsService.create({
        message: `Hi ${user.firstName}, your account has been verified successfully.`,
        subject: 'Account Verification',
        account: user.id,
      });

      return this.responseService.Response(
        true,
        'user successfully verified',
        HttpStatus.OK,
        { user },
      );
    } catch (error) {
      this.logger.error(
        `Something went wrong during email confirmation`,
        error.stack,
      );
      return this.responseService.Response(
        false,
        'something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { error:error },
      );
    }
  }

 


  async resendOtpAfterRegistration(dto: AuthresendOtpDto): Promise<any> {
    try {
      const existingOtp = await this.authOtpRepository.findOne({
        where: { email: dto.email },
      });

      

      if (!existingOtp) {
        return this.responseService.Response(
          false,
          'no existing found for this user',
          HttpStatus.NOT_FOUND,
          {},
        );
      }

      const now = new Date();
      if (now < existingOtp.resend_time) {
        return this.responseService.Response(
          false,
          'please wait before requesting a new otp',
          HttpStatus.BAD_REQUEST,
          {},
        );
      }

      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        return this.responseService.Response(
          false,
          'no user is associated with this otp',
          HttpStatus.NOT_FOUND,
          {},
        );

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

      await this.notificationsService.create({
        message: `Hi ${user.firstName}, otp resent after two minutes.`,
        subject: 'OTP resent After two Minutes',
        account: user.id,
      });
      return this.responseService.Response(
        true,
        'new otp sent ',
        HttpStatus.OK,
        { user },
      );
    } catch (error) {
      throw error;
    }
  }

  async resendExpiredOtp(dto: AuthresendOtpDto): Promise<any> {
    try {
      const existingOtp = await this.authOtpRepository.findOne({
        where: { email: dto.email },
      });

      if (!existingOtp) {
        return this.responseService.Response(
          false,
          'no existing otp found or this user',
          HttpStatus.NOT_FOUND,
          {},
        );
      }

      const now = new Date();
      if (now < existingOtp.expiration_time) {
        return this.responseService.Response(
          false,
          'current otp has not expired yet',
          HttpStatus.BAD_REQUEST,
          {},
        );
      }


      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        return this.responseService.Response(
          false,
          'no user is associated with this otp',
          HttpStatus.NOT_FOUND,
          {},
        );

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

      await this.notificationsService.create({
        message: `Hi ${user.firstName}, otp resent after expiring.`,
        subject: 'Expired OTP resent',
        account: user.id,
      });

      return this.responseService.Response(
        true,
        'new otp sent',
        HttpStatus.OK,
        { existingOtp },
      );
    } catch (error) {
      throw error;
    }
  }

  async forgotPassword(dto: AuthForgotPasswordDto): Promise<any> {
    try {
      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        return this.responseService.Response(
          false,
          'No user associated with email found',
          HttpStatus.NOT_FOUND,
          {},
        );

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

      // Store the hash and expiration time in the user table
      user.resetPasswordHash = hash;
      user.resetPasswordExpires = new Date(tokenExpires);
      await this.usersRepository.save(user);

      const frontendResetUrl = process.env.FRONTEND_RESET_URL;
      const resetLink = `${frontendResetUrl}?hash=${hash}&email=${user.email}`;

      await this.mailService.SendPasswordResetLinkMail(
        dto.email,
        resetLink,
        user.firstName,
      );

      return this.responseService.Response(
        true,
        'Password reset link sent',
        HttpStatus.OK,
        {},
      );
    } catch (error) {
      throw error;
    }
  }

  async resetPassword(dto: AuthResetPasswordDto): Promise<any> {
    try {
      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        return this.responseService.Response(
          false,
          'No user associated with email found',
          HttpStatus.NOT_FOUND,
          {},
        );

      // Verify the hash
      if (user.resetPasswordHash !== dto.hash) {
        return this.responseService.Response(
          false,
          'Invalid reset token',
          HttpStatus.BAD_REQUEST,
          {},
        );
      }

      // Check if the token has expired
      if (user.resetPasswordExpires < new Date()) {
        return this.responseService.Response(
          false,
          'Reset token has expired',
          HttpStatus.BAD_REQUEST,
          {},
        );
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(dto.password, await bcrypt.genSalt());

      // Update user's password and clear reset token fields
      user.password = hashedPassword;
      user.resetPasswordHash = '';
      //user.resetPasswordExpires = null;

      await this.usersRepository.update(user.id, user);

      // Delete all sessions for this user
      await this.sessionService.deleteByUserId({
        userId: user.id,
      });

      // Create a notification for the user
      await this.notificationsService.create({
        message: `${user.firstName}, you have successfully reset your password.`,
        subject: 'Password Reset',
        account: user.id,
      });

      return this.responseService.Response(
        true,
        'Password reset successfully',
        HttpStatus.OK,
        {},
      );
    } catch (error) {
      return this.responseService.Response(
        false,
        'Something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { error: error.message },
      );
    }
  }

  async me(user: UserEntity) {
    try {
      this.logger.log(`Fetching user data for user: ${user.id}`);
      const userProfile = await this.usersRepository.findOne({
        where: { id: user.id },
        relations: ['my_cards', 'my_transactions', 'my_wallet'],
      });
      if (!user)
        return this.responseService.Response(
          false,
          'user not found',
          HttpStatus.NOT_FOUND,
          {},
        );

      return this.responseService.Response(
        true,
        'logged in user returned successfully',
        HttpStatus.OK,
        { user },
      );
    } catch (error) {
      this.logger.error(
        `Error fetching user data: ${error.message}`,
        error.stack,
      );
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
        this.logger.warn(
          `Update failed: User not found for id: ${userJwtPayload.id}`,
        );
        return this.responseService.Response(
          false,
          'user not found',
          HttpStatus.NOT_FOUND,
          {},
        );
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
        const user = this.usersService.findById(userJwtPayload.id);
        return this.responseService.Response(
          true,
          'user details updated successfully',
          HttpStatus.OK,
          { user },
        );
      }
    } catch (error) {
      this.logger.error(`Update failed: ${error.message}`, error.stack);
      return this.responseService.Response(
        false,
        'something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { error: error },
      );
    }
  }

  private async handlePasswordUpdate(
    currentUser: User,
    userDto: AuthUpdateDto,
    userJwtPayload: JwtPayloadType,
  ): Promise<any> {
    if (!userDto.oldPassword) {
      return this.responseService.Response(
        false,
        'missing old password',
        HttpStatus.BAD_REQUEST,
        {},
      );
    }

    const isValidOldPassword = await this.comaprePassword(
      userDto.oldPassword,
      currentUser.password,
    );
    if (!isValidOldPassword) {
      return this.responseService.Response(
        false,
        'incorrect old password provided',
        HttpStatus.BAD_REQUEST,
        {},
      );
    }

    await this.sessionService.deleteByUserIdWithExclude({
      userId: currentUser.id,
      excludeSessionId: userJwtPayload.sessionId,
    });
  }

  async refreshToken(
    data: Pick<JwtRefreshPayloadType, 'sessionId' | 'hash'>,
  ): Promise<any> {
    try {
      this.logger.log(
        `Attempting to refresh token for session: ${data.sessionId}`,
      );
      const session = await this.sessionService.findById(data.sessionId);
      if (!session || session.hash !== data.hash) {
        this.logger.warn(
          `Token refresh failed: Invalid session or hash for session: ${data.sessionId}`,
        );
        return this.responseService.Response(
          false,
          'unauthorized',
          HttpStatus.UNAUTHORIZED,
          {},
        );
      }

      const user = await this.usersService.findById(session.user.id);
      if (!user?.role) {
        this.logger.warn(
          `Token refresh failed: User not found or no role for user: ${session.user.id}`,
        );
        return this.responseService.Response(
          false,
          'user not found',
          HttpStatus.UNAUTHORIZED,
          {},
        );
      }

      const hash = crypto
        .createHash('sha256')
        .update(randomStringGenerator())
        .digest('hex');
      await this.sessionService.update(session.id, { hash });

      this.logger.log(`Token refreshed successfully for user: ${user.id}`);
      return this.responseService.Response(
        true,
        'token refreshed successfully',
        HttpStatus.BAD_REQUEST,
        {
          id: session.user.id,
          role: user.role,
          sessionId: session.id,
          hash,
        },
      );
    } catch (error) {
      this.logger.error(`Token refresh failed: ${error.message}`, error.stack);
      return this.responseService.Response(
        false,
        'something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { error: error },
      );
    }
  }

  async softDelete(user: User): Promise<any> {
    try {
      this.logger.log(`Soft deleting user: ${user.id}`);
      await this.usersService.remove(user.id);
      return this.responseService.Response(
        true,
        'user deleted successfully',
        HttpStatus.OK,
        {},
      );
    } catch (error) {
      this.logger.error(`Soft delete failed: ${error.message}`, error.stack);
      return this.responseService.Response(
        false,
        'something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { error: error },
      );
    }
  }

  async logout(data: Pick<JwtRefreshPayloadType, 'sessionId'>): Promise<any> {
    try {
      this.logger.log(`Logging out session: ${data.sessionId}`);
      await this.sessionService.deleteById(data.sessionId);
      return this.responseService.Response(
        true,
        'logout successful',
        HttpStatus.OK,
        {},
      );
    } catch (error) {
      this.logger.error(`Logout failed: ${error.message}`, error.stack);
      return this.responseService.Response(
        false,
        'something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { error: error },
      );
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
