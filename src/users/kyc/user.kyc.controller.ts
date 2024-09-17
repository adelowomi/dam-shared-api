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
import { KycService } from './user.kyc.service';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiCreatedResponse,
  ApiTags,
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

@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'))
@ApiTags('KYC')
@Controller({
  path: 'kyc',
  version: '1',
})
export class KycController {
  constructor(private readonly kycService: KycService) {}

  @Post('initiatiate-nationalId-verification')
  async initiatePassportPhotographVerification(
    @Req() req,
    @Body() dto: NigerianIdDto,
  ) {
    return await this.kycService.identifyID(req.user, dto);
  }

  @Patch('proof-of-life-verification')
  async initiateSelfieVerification(@Body() body: any, @Req() req) {
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
  @Patch('upload-signature')
  async uploadSignature(@Req() req, @UploadedFile() file: Express.Multer.File):Promise<StandardResponse<UserEntity>> {
    return await this.kycService.confirmSignatureUpload(req.user, file);
  }

  
  @Patch('update-pep-details')
  async updatePepDetails(@Req() req, @Body() dto: PepDto):Promise<StandardResponse<UserEntity>> {
    return await this.kycService.updatePepDetails(req.user, dto);
  }


  @Patch('update-employment-details')
  async updateEmploymentDetails(@Req() req, @Body() dto: EmploymentDetailsDto) :Promise<StandardResponse<UserEntity>>{
    return await this.kycService.updateEmploymentDetails(req.user, dto);
  }

  
  @Patch('update-bank-details')
  async updateBankDetails(@Req() req, @Body() dto: BankDetailsDto):Promise<StandardResponse<UserEntity>> {
    return await this.kycService.updateBankDetails(req.user, dto);
  }


  @Patch('update-nextOfkin-details')
  async updateNextOfkin(@Req() req, @Body() dto: NextOfKinDto):Promise<StandardResponse<UserEntity>> {
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
  @Patch('upload-proof-of-address')
  async uploadAddressProof(
    @Req() req,
    @UploadedFile() file: Express.Multer.File,
  ) :Promise<StandardResponse<UserEntity>>{
    return await this.kycService.uploadAddressProof(req.user, file);
  }

  
  @Patch('update-tax-details')
  async updateTaxDetails(@Req() req, @Body() dto: TaxDetailsDto) :Promise<StandardResponse<UserEntity>>{
    return await this.kycService.updateTaxDetails(req.user, dto);
  }

 
    @Get('kyc-progress')
    async getkycProgress(@Req() req) :Promise<StandardResponse<number>>{
      return await this.kycService.getKycProgress(req.user);
    }
  }

