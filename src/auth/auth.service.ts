import {
  Injectable,
  HttpStatus,
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
import {
  ResponseService,
  StandardResponse,
} from '../utils/services/response.service';
import { RefreshResponseDto } from './dto/refresh-response.dto';

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

  async validateLogin(
    loginDto: AuthEmailLoginDto,
  ): Promise<StandardResponse<LoginResponseDto>> {
    try {
      this.logger.log(`
        Attempting to validate login for email: ${loginDto.email}`);
      const user = await this.usersRepository.findOne({
        where: { email: loginDto.email },
      });
      if (!user) {
        this.logger.warn(`
          Login failed: User not found for email: ${loginDto.email}`);
        return this.responseService.notFound('user not found');
      }

      const comparepass = await this.comaprePassword(
        loginDto.password,
        user.password,
      );
      if (!comparepass)
        return this.responseService.notFound('incorrect password');

      if (!user.isVerified)
        return this.responseService.forbidden('user not verified');

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
        { ...tokens, user },
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
      this.logger.error(
        `Session creation failed: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error creating session');
    }
  }

  async register(dto: AuthRegisterDto): Promise<StandardResponse<UserEntity>> {
    try {
      this.logger.log(
        `Attempting to register new user with email: ${dto.email}`,
      );

      const existingUser = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (existingUser) {
        return this.responseService.badRequest('user already exists');
      }

      const age = this.calculateAge(dto.DOB);
      if (age < 18) {
        this.logger.warn(
          `Registration failed: User age (${age}) is below approved age`,
        );
        return this.responseService.badRequest(
          'user age is below approved age',
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
      return this.responseService.success('user registered successfully', user);
    } catch (error) {
      this.logger.error(`Registration failed: ${error.message}`, error.stack);
      return this.responseService.internalServerError('Error registering user');
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

  async confirmEmail(
    dto: AuthConfirmEmailDto,
  ): Promise<StandardResponse<UserEntity>> {
    try {
      const findotp = await this.authOtpRepository.findOne({
        where: { otp: dto.otp },
      });
      if (!findotp)
        return this.responseService.badRequest('invalid otp provided');

      //find if the otp is expired
      if (findotp.expiration_time <= new Date())
        return this.responseService.badRequest('otp has expired');

      // Find the admin associated with the OTP
      const user = await this.usersRepository.findOne({
        where: { email: findotp.email },
      });
      if (!user)
        return this.responseService.notFound(
          'no user associated with this otp',
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

      return this.responseService.success('email confirmed successfully', user);
    } catch (error) {
      this.logger.error(
        `Something went wrong during email confirmation`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error confirming email',
        error,
      );
    }
  }

  async resendOtpAfterRegistration(
    dto: AuthresendOtpDto,
  ): Promise<StandardResponse<UserEntity>> {
    try {
      const existingOtp = await this.authOtpRepository.findOne({
        where: { email: dto.email },
      });

      if (!existingOtp) {
        return this.responseService.badRequest(
          'no existing otp found or this user',
        );
      }

      const now = new Date();
      if (now < existingOtp.resend_time) {
        return this.responseService.badRequest(
          'current otp has not expired yet',
        );
      }

      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        return this.responseService.notFound(
          'no user is associated with this otp',
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
      return this.responseService.success('new otp sent', user);
    } catch (error) {
      throw error;
    }
  }

  async resendExpiredOtp(
    dto: AuthresendOtpDto,
  ): Promise<StandardResponse<AuthOtpEntity>> {
    try {
      const existingOtp = await this.authOtpRepository.findOne({
        where: { email: dto.email },
      });

      if (!existingOtp) {
        return this.responseService.notFound(
          'no existing otp found or this user',
        );
      }

      const now = new Date();
      if (now < existingOtp.expiration_time) {
        return this.responseService.badRequest(
          'current otp has not expired yet',
        );
      }

      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        return this.responseService.notFound(
          'no user is associated with this otp',
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

      return this.responseService.success('new otp sent', existingOtp);
    } catch (error) {
      throw error;
    }
  }

  async forgotPassword(
    dto: AuthForgotPasswordDto,
  ): Promise<StandardResponse<any>> {
    try {
      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        return this.responseService.notFound('no user associated with email');

      const tokenExpiresIn = this.configService.getOrThrow(
        'auth.forgotExpires',
        {
          infer: true,
        },
      );

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

      console.log(hash);
      // Store the hash and expiration time in the user table
      user.resetPasswordHash = hash;
      user.resetPasswordExpires = new Date(tokenExpires);
      await this.usersRepository.save(user);

      const frontendResetUrl =
        'https://stg.dam.sofriwebservices.com/reset-password';
      const resetLink = `${frontendResetUrl}?token=${hash}&email=${user.email}`;

      await this.mailService.SendPasswordResetLinkMail(
        dto.email,
        resetLink,
        user.firstName,
      );

      return this.responseService.success('reset link sent', {});
    } catch (error) {
      throw error;
    }
  }

  async resetPassword(
    dto: AuthResetPasswordDto,
  ): Promise<StandardResponse<boolean>> {
    try {
      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        return this.responseService.notFound('no user associated with email');

      // Verify the hash
      if (user.resetPasswordHash !== dto.hash) {
        return this.responseService.badRequest('Invalid reset token');
      }

      // Check if the token has expired
      if (user.resetPasswordExpires < new Date()) {
        return this.responseService.badRequest('Reset token has expired');
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(
        dto.password,
        await bcrypt.genSalt(),
      );

      // Update user's password and clear reset token fields
      // Update user's password and clear reset token fields
      await this.usersRepository.update(user.id, {
        password: hashedPassword,
        resetPasswordHash: '',
      });

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

      return this.responseService.success('password reset successful', true);
    } catch (error) {
      console.log(error);
      return this.responseService.internalServerError(
        'Error resetting password',
        error,
      );
    }
  }

  async me(user: UserEntity): Promise<StandardResponse<UserEntity>> {
    try {
      this.logger.log(`Fetching user data for user: ${user.id}`);
      const userProfile = await this.usersRepository.findOne({
        where: { id: user.id },
        relations: ['my_cards', 'my_transactions', 'my_wallet'],
      });
      if (!user)
        return this.responseService.notFound('no user associated with email');

      return this.responseService.success(
        'user data fetched',
        userProfile as UserEntity,
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
  ): Promise<StandardResponse<User>> {
    try {
      this.logger.log(`Attempting to update user: ${userJwtPayload.id}`);
      const currentUser = await this.usersService.findById(userJwtPayload.id);
      if (!currentUser) {
        this.logger.warn(
          `Update failed: User not found for id: ${userJwtPayload.id}`,
        );
        return this.responseService.notFound('user not found');
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
        const user = await this.usersService.findById(userJwtPayload.id);
        return this.responseService.success('email updated', user);
      }
      return this.responseService.success('user updated', currentUser);
    } catch (error) {
      this.logger.error(`Update failed: ${error.message}`, error.stack);
      return this.responseService.internalServerError(
        'Error updating user',
        error,
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
  ): Promise<StandardResponse<RefreshResponseDto>> {
    try {
      this.logger.log(
        `Attempting to refresh token for session: ${data.sessionId}`,
      );
      const session = await this.sessionService.findById(data.sessionId);
      if (!session || session.hash !== data.hash) {
        this.logger.warn(
          `Token refresh failed: Invalid session or hash for session: ${data.sessionId}`,
        );
        return this.responseService.badRequest('invalid session or hash');
      }

      const user = await this.usersService.findById(session.user.id);
      if (!user?.role) {
        this.logger.warn(
          `Token refresh failed: User not found or no role for user: ${session.user.id}`,
        );
        return this.responseService.badRequest('user not found or no role');
      }

      const hash = crypto
        .createHash('sha256')
        .update(randomStringGenerator())
        .digest('hex');
      await this.sessionService.update(session.id, { hash });

      const tokens = await this.getTokensData({
        id: user.id,
        role: user.role,
        sessionId: session.id,
        hash: session.hash,
      });

      this.logger.log(`Token refreshed successfully for user: ${user.id}`);
      return this.responseService.success('token refreshed', {
        ...tokens,
        user,
      });
    } catch (error) {
      this.logger.error(`Token refresh failed: ${error.message}`, error.stack);
      return this.responseService.internalServerError(
        'Error refreshing token',
        error,
      );
    }
  }

  async softDelete(user: User): Promise<StandardResponse<boolean>> {
    try {
      this.logger.log(`Soft deleting user: ${user.id}`);
      await this.usersService.remove(user.id);
      return this.responseService.success('user deleted successfully', true);
    } catch (error) {
      this.logger.error(`Soft delete failed: ${error.message}`, error.stack);
      return this.responseService.internalServerError(
        'Error deleting user',
        error,
      );
    }
  }

  async logout(
    data: Pick<JwtRefreshPayloadType, 'sessionId'>,
  ): Promise<StandardResponse<boolean>> {
    try {
      this.logger.log(`Logging out session: ${data.sessionId}`);
      await this.sessionService.deleteById(data.sessionId);
      return this.responseService.success('logout successful', true);
    } catch (error) {
      this.logger.error(`Logout failed: ${error.message}`, error.stack);
      return this.responseService.internalServerError(
        'Error logging out',
        error,
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
        typeof tokenExpiresIn === 'string'
          ? ms(tokenExpiresIn)
          : tokenExpiresIn;
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
      this.logger.error(
        `Token generation failed: ${error.message}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error generating tokens');
    }
  }
}
