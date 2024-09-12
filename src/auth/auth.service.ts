import {
  Injectable,
  HttpStatus,
  UnprocessableEntityException,
  NotFoundException,
  UnauthorizedException,
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

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    @InjectRepository(UserEntity)
    private readonly usersRepository: Repository<UserEntity>,
    @InjectRepository(AuthOtpEntity)
    private readonly authOtpRepository: Repository<AuthOtpEntity>,
    private usersService: UserService,
    private sessionService: SessionService,
    private mailService: Mailer,
    //private  notificationsService: NotificationsService,
    private configService: ConfigService,
  ) {}

  async validateLogin(loginDto: AuthEmailLoginDto): Promise<LoginResponseDto> {
    const user = await this.usersService.findByEmail(loginDto.email);
    if (!user) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { email: 'notFound' },
      });
    }

    this.validateUserForLogin(user);
    await this.comaprePassword(loginDto.password, user.password);

    const session = await this.createSession(user);
    const tokens = await this.getTokensData({
      id: user.id,
      role: user.role,
      sessionId: session.id,
      hash: session.hash,
    });

    return { ...tokens, user };
  }

  private validateUserForLogin(user: User): void {
    if (user.provider !== AuthProvidersEnum.email) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { email: `needLoginViaProvider:${user.provider}` },
      });
    }

    if (!user.isVerified) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { email: 'userNotVerified' },
      });
    }
  }

  private async comaprePassword(userpassword, dbpassword): Promise<boolean> {
    return await bcrypt.compare(userpassword, dbpassword);
  }

  private async createSession(user: User) {
    const hash = crypto
      .createHash('sha256')
      .update(randomStringGenerator())
      .digest('hex');

    return this.sessionService.create({ user, hash });
  }

  async register(dto: AuthRegisterDto): Promise<{ user: User }> {
    const age = this.calculateAge(dto.DOB);
    if (age < 18) {
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

    // await this.notificationsService.create({
    //   message: `Welcome ${user.firstName}, your account has been created successfully.`,
    //   subject: 'Account Creation',
    //   account: user.id,
    // });

    return { user };
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
    const existingUser = await this.usersService.findByEmail(email);
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

  private async createUser(userData: Partial<User>): Promise<User> {
    const userPayload = {
      ...userData,
      role: RoleEnum.USER,
      status: StatusEnum.ACTIVE,
      provider: AuthProvidersEnum.email,
    };
    return this.usersRepository.save(this.usersRepository.create(userPayload));
  }

  async confirmEmail(dto: AuthConfirmEmailDto): Promise<void> {
    const otpRecord = await this.verifyOtp(dto.otp, dto.email);
    const user = await this.getUserForEmailConfirmation(dto.email);

    await this.updateUserAfterConfirmation(user);
    await this.markOtpAsVerified(otpRecord);
    await this.mailService.WelcomeMail(user.email, user.firstName);
    //await this.createVerificationNotification(user);
  }

  private async verifyOtp(otp: string, email: string): Promise<AuthOtpEntity> {
    const otpRecord = await this.authOtpRepository.findOne({
      where: { otp, email },
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

  private async getUserForEmailConfirmation(email: string): Promise<User> {
    const user = await this.usersService.findByEmail(email);
    if (!user || user.status !== StatusEnum.INACTIVE) {
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
    user.userRegisteredAndVerified = true;
    user.kycCompletionPercentage = Math.min(
      user.kycCompletionPercentage + 10,
      100,
    );
    await this.usersService.update(user.id, user);
  }

  private async markOtpAsVerified(otpRecord: AuthOtpEntity): Promise<void> {
    otpRecord.verified = true;
    await this.authOtpRepository.save(otpRecord);
  }

  // private async createVerificationNotification(user: User): Promise<void> {
  //   await this.notificationsService.create({
  //     message: `Hi ${user.firstName}, your account has been verified successfully.`,
  //     subject: 'Account Verification',
  //     account: user.id,
  //   });
  // }

  async resendOtpAfterRegistration(dto: AuthresendOtpDto): Promise<void> {
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
  }

  async resendExpiredOtp(dto: AuthresendOtpDto): Promise<void> {
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
  }

  async forgotPassword(dto: AuthForgotPasswordDto): Promise<void> {
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
  }

  async resetPassword(dto: AuthResetPasswordDto): Promise<void> {
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
  }

  async me(userJwtPayload: JwtPayloadType): Promise<User | null> {
    return this.usersService.findById(userJwtPayload.id);
  }

  async update(
    userJwtPayload: JwtPayloadType,
    userDto: AuthUpdateDto,
  ): Promise<any> {
    const currentUser = await this.usersService.findById(userJwtPayload.id);
    if (!currentUser) {
      throw new UnprocessableEntityException({
        status: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: { user: 'userNotFound' },
      });
    }

    if (userDto.password) {
      await this.handlePasswordUpdate(currentUser, userDto, userJwtPayload);
    }

    if (userDto.email && userDto.email !== currentUser.email) {
      currentUser.email = userDto.email;

      delete userDto.email;
      delete userDto.oldPassword;

      await this.usersRepository.save(currentUser);
      return this.usersService.findById(userJwtPayload.id);
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

    const isValidOldPassword = await this.comaprePassword(
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
    const session = await this.sessionService.findById(data.sessionId);
    if (!session || session.hash !== data.hash) {
      throw new UnauthorizedException();
    }

    const user = await this.usersService.findById(session.user.id);
    if (!user?.role) {
      throw new UnauthorizedException();
    }

    const hash = crypto
      .createHash('sha256')
      .update(randomStringGenerator())
      .digest('hex');
    await this.sessionService.update(session.id, { hash });

    return this.getTokensData({
      id: session.user.id,
      role: user.role,
      sessionId: session.id,
      hash,
    });
  }

  async softDelete(user: User): Promise<void> {
    await this.usersService.remove(user.id);
  }

  async logout(data: Pick<JwtRefreshPayloadType, 'sessionId'>): Promise<void> {
    await this.sessionService.deleteById(data.sessionId);
  }

  private async getTokensData(data: {
    id: User['id'];
    role: User['role'];
    sessionId: Session['id'];
    hash: Session['hash'];
  }): Promise<Omit<LoginResponseDto, 'user'>> {
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
  }
}
