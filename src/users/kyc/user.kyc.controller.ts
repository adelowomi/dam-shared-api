import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  InternalServerErrorException,
  Patch,
  Post,
  Req,
  Session,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
console.log('🚀 ~ Req:', Req);
import { KycService } from './user.kyc.service';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiTags,
  getSchemaPath,
} from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../roles/roles.guard';
import { UserEntity } from '../infrastructure/persistence/relational/entities/user.entity';
import { FileInterceptor } from '@nestjs/platform-express';
import { PepDto } from '../dto/KEP.dto';
import { EmploymentDetailsDto } from '../dto/employment-details.dto';
import { BankDetailsDto } from '../dto/bankdetails.dto';
import { AddressProofDto } from '../dto/address-proof.dto';
import { User } from '../domain/user';
import { NigerianIdDto } from '../dto/nigerianid.dto';
import { NextOfKinDto } from '../dto/next-of-kin.dto';
import { TaxDetailsDto } from '../dto/tax-details.dto';
import { StandardResponse } from '../../utils/services/response.service';
import { PersnalIdVerificationModel } from '../dto/personal-id';
import { SmileJobWebHookDto } from '../dto/smile-webhook.dto';
import { ResolveBankAccountResponse } from '../../utils/services/models/PayStaackStandardResponse';

@ApiBearerAuth()
@ApiTags('KYC')
@Controller({
  path: 'kyc',
  version: '1',
})
export class KycController {
  constructor(private readonly kycService: KycService) {}

  @Post('initiatiate-nationalId-verification')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<any>),
        },
        {
          properties: {
            payload: {},
          },
        },
      ],
    },
  })
  async initiatePassportPhotographVerification(
    @Req() req,
    @Body() dto: NigerianIdDto,
  ): Promise<StandardResponse<any>> {
    return await this.kycService.identifyID(req.user, dto);
  }

  @Patch('proof-of-life-verification')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<any>),
        },
        {
          properties: {
            payload: {},
          },
        },
      ],
    },
  })
  async initiateSelfieVerification(
    @Body() body: any,
    @Req() req,
  ): Promise<StandardResponse<any>> {
    const { images, partner_params } = body;

    if (!images || images.length === 0) {
      throw new BadRequestException('No images provided.');
    }

    // Check if partner_params exists and has libraryVersion
    const libraryVersion = partner_params?.libraryVersion || 'default_version';

    if (!libraryVersion) {
      throw new BadRequestException('Library version is required.');
    }

    try {
      const result = await this.kycService.submitSelfieJob(
        req.user,
        images,
        libraryVersion,
      );
      return result;
    } catch (error) {
      console.error('Failed to submit selfie for verification:', error);
      throw new InternalServerErrorException(
        'Failed to submit selfie for KYC verification',
      );
    }
  }

  @ApiConsumes('multipart/form-data')
  @UseGuards(AuthGuard('jwt'))
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        signature: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  @UseInterceptors(FileInterceptor('signature'))
  @UseGuards(AuthGuard('jwt'))
  @Patch('upload-signature')
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<UserEntity>),
        },
        {
          properties: {
            payload: {
              $ref: getSchemaPath(UserEntity),
            },
          },
        },
      ],
    },
  })
  async uploadSignature(
    @Req() req,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<StandardResponse<UserEntity>> {
    return await this.kycService.confirmSignatureUpload(req.user, file);
  }

  @Patch('update-pep-details')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<UserEntity>),
        },
        {
          properties: {
            payload: {
              $ref: getSchemaPath(UserEntity),
            },
          },
        },
      ],
    },
  })
  @UseGuards(AuthGuard('jwt'))
  async updatePepDetails(
    @Req() req,
    @Body() dto: PepDto,
  ): Promise<StandardResponse<UserEntity>> {
    return await this.kycService.updatePepDetails(req.user, dto);
  }

  @Patch('update-employment-details')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<UserEntity>),
        },
        {
          properties: {
            payload: {
              $ref: getSchemaPath(UserEntity),
            },
          },
        },
      ],
    },
  })
  async updateEmploymentDetails(
    @Req() req,
    @Body() dto: EmploymentDetailsDto,
  ): Promise<StandardResponse<UserEntity>> {
    return await this.kycService.updateEmploymentDetails(req.user, dto);
  }

  @Patch('update-bank-details')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<UserEntity>),
        },
        {
          properties: {
            payload: {
              $ref: getSchemaPath(UserEntity),
            },
          },
        },
      ],
    },
  })
  async updateBankDetails(
    @Req() req,
    @Body() dto: BankDetailsDto,
  ): Promise<StandardResponse<UserEntity>> {
    return await this.kycService.updateBankDetails(req.user, dto);
  }

  @Patch('update-nextOfkin-details')
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<UserEntity>),
        },
        {
          properties: {
            payload: {
              $ref: getSchemaPath(UserEntity),
            },
          },
        },
      ],
    },
  })
  async updateNextOfkin(
    @Req() req,
    @Body() dto: NextOfKinDto,
  ): Promise<StandardResponse<UserEntity>> {
    return await this.kycService.updateNextOfkin(req.user, dto);
  }

  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        addressProof: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  @UseInterceptors(FileInterceptor('addressProof'))
  @UseGuards(AuthGuard('jwt'))
  @Patch('upload-proof-of-address')
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<UserEntity>),
        },
        {
          properties: {
            payload: {
              $ref: getSchemaPath(UserEntity),
            },
          },
        },
      ],
    },
  })
  async uploadAddressProof(
    @Req() req,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<StandardResponse<UserEntity>> {
    return await this.kycService.uploadAddressProof(req.user, file);
  }

  @Patch('update-tax-details')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<UserEntity>),
        },
        {
          properties: {
            payload: {
              $ref: getSchemaPath(UserEntity),
            },
          },
        },
      ],
    },
  })
  async updateTaxDetails(
    @Req() req,
    @Body() dto: TaxDetailsDto,
  ): Promise<StandardResponse<UserEntity>> {
    return await this.kycService.updateTaxDetails(req.user, dto);
  }

  @Get('kyc-progress')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<UserEntity>),
        },
        {
          properties: {
            payload: {},
          },
        },
      ],
    },
  })
  async getkycProgress(
    @Req() req,
  ): Promise<
    StandardResponse<{ steps: Record<string, boolean>; percentage: number }>
  > {
    return await this.kycService.getKycProgressNew(req.user);
  }

  @Post('initiate-personal-id-verification')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<any>),
        },
        {
          properties: {
            payload: {},
          },
        },
      ],
    },
  })
  async initiatePersonalIdVerification(
    @Req() req,
  ): Promise<StandardResponse<any>> {
    return await this.kycService.personalIdVerification({
      images: req.body.images,
      partner_params: req.body.partner_params,
    });
  }

  @Post('smile-webhook')
  @UseGuards(AuthGuard('anonymous'))
  public smileWebhook(@Req() req, @Body() dto: SmileJobWebHookDto) {
    console.log('🚀 ~ KycController ~ smileWebhook ~ req:', req.body);

    return this.kycService.smileWebhook(req.body);
  }

  @Post('initiate-verification')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<any>),
        },
        {
          properties: {
            payload: {},
          },
        },
      ],
    },
  })
  async initiateVerification(@Req() req): Promise<StandardResponse<any>> {
    return await this.kycService.initiateSMileIdLinkVerification(req.user);
  }

  @Post('resolve-bank-account')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    schema: {
      allOf: [
        {
          $ref: getSchemaPath(StandardResponse<any>),
        },
        {
          properties: {
            payload: {},
          },
        },
      ],
    },
  })
  async resolveBankAccount(
    @Req() req,
    @Body() model: BankDetailsDto,
  ): Promise<StandardResponse<ResolveBankAccountResponse>> {
    return await this.kycService.resolveBankAccount(model);
  }
}
