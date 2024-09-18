import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Request,
  Post,
  UseGuards,
  Patch,
  Delete,
  SerializeOptions,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiTags,
  ApiExtraModels,
  getSchemaPath,
} from '@nestjs/swagger';
import { AuthEmailLoginDto } from './dto/auth-email-login.dto';
import { AuthForgotPasswordDto } from './dto/auth-forgot-password.dto';
import { AuthConfirmEmailDto } from './dto/auth-confirm-email.dto';
import { AuthResetPasswordDto } from './dto/auth-reset-password.dto';
import { AuthUpdateDto } from './dto/auth-update.dto';
import { AuthGuard } from '@nestjs/passport';
import { AuthRegisterDto } from './dto/auth-register-login.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { User } from '../users/domain/user';
import { RefreshResponseDto } from './dto/refresh-response.dto';
import { AuthresendOtpDto } from './dto/resendOtp.dto';
import { StandardResponse } from '../utils/services/response.service';
import { UserEntity } from '../users/infrastructure/persistence/relational/entities/user.entity';
import { AuthOtpEntity } from '../users/infrastructure/persistence/relational/entities/authOtp.entity';

@ApiTags('Auth')
@Controller({
  path: 'auth',
  version: '1',
})
@ApiExtraModels(
  StandardResponse,
  User,
  UserEntity,
  AuthOtpEntity,
  LoginResponseDto,
  RefreshResponseDto,
)
export class AuthController {
  constructor(private readonly service: AuthService) {}

  @SerializeOptions({
    groups: ['me'],
  })
  @Post('login')
  @ApiOkResponse({
    // type: StandardResponse<LoginResponseDto>,
    schema: {
      allOf: [
        { $ref: getSchemaPath(StandardResponse<LoginResponseDto>) },
        {
          properties: {
            payload: {
              $ref: getSchemaPath(LoginResponseDto),
            },
          },
        },
      ],
    },
  })
  public login(
    @Body() loginDto: AuthEmailLoginDto,
  ): Promise<StandardResponse<LoginResponseDto>> {
    return this.service.validateLogin(loginDto);
  }

  @Post('register')
  @ApiOkResponse({
    type: StandardResponse<UserEntity>,
  })
  async register(
    @Body() createUserDto: AuthRegisterDto,
  ): Promise<StandardResponse<UserEntity>> {
    return this.service.register(createUserDto);
  }

  @Post('confirm-email')
  @ApiOkResponse({
    type: StandardResponse<UserEntity>,
  })
  async confirmEmail(
    @Body() confirmEmailDto: AuthConfirmEmailDto,
  ): Promise<StandardResponse<UserEntity>> {
    return this.service.confirmEmail(confirmEmailDto);
  }

  @Post('resend-otp')
  @ApiOkResponse({
    type: StandardResponse<UserEntity>,
  })
  async resendOtpAfterRegistration(
    @Body() dto: AuthresendOtpDto,
  ): Promise<StandardResponse<UserEntity>> {
    return this.service.resendOtpAfterRegistration(dto);
  }

  @Post('resend-expired-otp')
  @ApiOkResponse({
    type: StandardResponse<AuthOtpEntity>,
  })
  async resendExpiredOtp(
    @Body() dto: AuthresendOtpDto,
  ): Promise<StandardResponse<AuthOtpEntity>> {
    return this.service.resendExpiredOtp(dto);
  }

  @Post('forgot-password')
  @ApiOkResponse({
    type: StandardResponse<any>,
  })
  async forgotPassword(
    @Body() forgotPasswordDto: AuthForgotPasswordDto,
  ): Promise<StandardResponse<any>> {
    return this.service.forgotPassword(forgotPasswordDto);
  }

  @Post('reset-password')
  @ApiOkResponse({
    type: StandardResponse<boolean>,
  })
  resetPassword(
    @Body() resetPasswordDto: AuthResetPasswordDto,
  ): Promise<StandardResponse<boolean>> {
    return this.service.resetPassword(resetPasswordDto);
  }

  @ApiBearerAuth()
  @SerializeOptions({ groups: ['me'] })
  @Get('me')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({ type: StandardResponse<UserEntity> })
  @HttpCode(HttpStatus.OK)
  public me(@Req() request): Promise<StandardResponse<UserEntity>> {
    return this.service.me(request.user);
  }

  @ApiBearerAuth()
  @ApiOkResponse({ type: StandardResponse<RefreshResponseDto> })
  @SerializeOptions({ groups: ['me'] })
  @Post('refresh')
  @UseGuards(AuthGuard('jwt-refresh'))
  @HttpCode(HttpStatus.OK)
  public refresh(
    @Request() request,
  ): Promise<StandardResponse<RefreshResponseDto>> {
    return this.service.refreshToken({
      sessionId: request.user.sessionId,
      hash: request.user.hash,
    });
  }

  @ApiBearerAuth()
  @ApiOkResponse({ type: StandardResponse<boolean> })
  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.NO_CONTENT)
  public async logout(@Request() request): Promise<StandardResponse<boolean>> {
    return await this.service.logout({ sessionId: request.user.sessionId });
  }

  @ApiBearerAuth()
  @SerializeOptions({ groups: ['me'] })
  @Patch('me')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: StandardResponse<User> })
  public update(
    @Request() request,
    @Body() userDto: AuthUpdateDto,
  ): Promise<StandardResponse<User>> {
    return this.service.update(request.user, userDto);
  }

  @ApiBearerAuth()
  @Delete('me')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({ type: StandardResponse<boolean> })
  @HttpCode(HttpStatus.NO_CONTENT)
  public async delete(@Request() request): Promise<StandardResponse<boolean>> {
    return this.service.softDelete(request.user);
  }
}
