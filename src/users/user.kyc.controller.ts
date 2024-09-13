import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Patch,
  Post,
  Req,
  Session,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { KycService } from './user.kyc.service';
import { ApiBearerAuth, ApiCreatedResponse, ApiTags } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../roles/roles.guard';
import { UserEntity } from './infrastructure/persistence/relational/entities/user.entity';
import { FileInterceptor } from '@nestjs/platform-express';
import { PepDto } from './dto/KEP.dto';
import { EmploymentDetailsDto } from './dto/employment-details.dto';
import { BankDetailsDto } from './dto/bankdetails.dto';
import { AddressProofDto } from './dto/address-proof.dto';
import { User } from './domain/user';

@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'), RolesGuard)
@ApiTags('KYC')
@Controller({
  path: 'kyc',
  version: '1',
})
export class KycController {
  constructor(private readonly kycService: KycService) {}

  @Post('initiatiate-passportPhotograph-verification')
  @HttpCode(HttpStatus.OK)
  async initiatePassportPhotographVerification(@Req() req) {
    return await this.kycService.initiatePassportPhotographVerification(
      req.user,
    );
  }

  @ApiCreatedResponse({ type: User })
  @Patch('complete-passport-photograph-verification')
  @HttpCode(HttpStatus.OK)
  async completePassportPhotographVerification(@Req() req, @Session() session) {
    return await this.kycService.completePassportPhotographVerification(
      req.user,
      session,
    );
  }

  @ApiCreatedResponse({ type: User })
  @UseInterceptors(FileInterceptor('signature'))
  @Patch('upload-signature')
  @HttpCode(HttpStatus.OK)
  async uploadSignature(
    @Req() req,
    @UploadedFile() file: Express.MulterS3.File,
  ) {
    return await this.kycService.uploadSignature(req.user, file);
  }

  @ApiCreatedResponse({ type: User })
  @Patch('update-pep-details')
  @HttpCode(HttpStatus.OK)
  async updatePepDetails(@Req() req, @Body() dto: PepDto) {
    return await this.kycService.updatePepDetails(req.user, dto);
  }

  @ApiCreatedResponse({ type: User })
  @Patch('update-employment-details')
  @HttpCode(HttpStatus.OK)
  async updateEmploymentDetails(@Req() req, @Body() dto: EmploymentDetailsDto) {
    return await this.kycService.updateEmploymentDetails(req.user, dto);
  }

  @ApiCreatedResponse({ type: User })
  @Patch('update-bank-details')
  @HttpCode(HttpStatus.OK)
  async updateBankDetails(@Req() req, @Body() dto: BankDetailsDto) {
    return await this.kycService.updateBankDetails(req.user, dto);
  }

  @ApiCreatedResponse({ type: User })
  @Patch('update-nextOfkin-details')
  @HttpCode(HttpStatus.OK)
  async updateNextOfkin(@Req() req, @Body() dto: BankDetailsDto) {
    return await this.kycService.updateBankDetails(req.user, dto);
  }

  @ApiCreatedResponse({ type: User })
  @UseInterceptors(FileInterceptor('addressProof'))
  @Patch('update-nextOfkin-details')
  @HttpCode(HttpStatus.OK)
  async uploadAddressProof(
    @Req() req,
    @Body() dto: AddressProofDto,
    @UploadedFile() file: Express.MulterS3.File,
  ) {
    return await this.kycService.uploadAddressProof(req.user, file, dto);
  }
}
