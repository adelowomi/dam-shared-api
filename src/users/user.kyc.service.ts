import {
  Injectable,
  HttpStatus,
  UnprocessableEntityException,
  NotFoundException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotificationsService } from '../notifications/notifications.service';
import { ZanzibarService } from '../utils/services/zanibar.service';
import { SmileService } from '../utils/services/smileID.service';
import { FilesS3Service } from '../files/infrastructure/uploader/s3/files.service';
import { UserEntity } from './infrastructure/persistence/relational/entities/user.entity';
import { PepDto } from './dto/KEP.dto';
import { EmploymentDetailsDto } from './dto/employment-details.dto';
import { NextOfKinDto } from './dto/next-of-kin.dto';
import { BankDetailsDto } from './dto/bankdetails.dto';
import { AddressProofDto } from './dto/address-proof.dto';
import { GovernmentIdDto } from './dto/goverenment-id.dto';
import { TaxDetailsDto } from './dto/tax-details.dto';
import { User } from './domain/user';

@Injectable()
export class KycService {
  private readonly logger = new Logger(KycService.name);

  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private  notificationService: NotificationsService,
    private readonly zanibarService: ZanzibarService,
    private readonly smileService: SmileService,
    private readonly filesS3Service: FilesS3Service,
  ) {}

  // Passport Photograph Verification Initiation
  async initiatePassportPhotographVerification(
    user: User,
  ): Promise<string> {
    try {
      const redirectUrl =
        await this.smileService.initiatePassportPhotographVerification(
          user.id.toString(),
        );

      user.passportPhotographVerificationInitiated = true;
      await this.userRepository.save(user);

      this.logger.log(`Passport verification initiated for user ${user.id}`);
      return redirectUrl;
    } catch (error) {
      this.logger.error(
        `Failed to initiate passport verification for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Failed to initiate passport photograph verification',
      );
    }
  }

  // Completing Passport Photograph Verification
  async completePassportPhotographVerification(
    user: User,
    sessionId: string,
  ): Promise<User> {
    try {
      const verificationResult =
        await this.smileService.verifyPassportPhotographSession(sessionId);

      if (!verificationResult.success) {
        throw new UnprocessableEntityException({
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          error: 'passportVerificationFailed',
        });
      }

      user.passportPhotographVerificationInitiated = false; // Reset after completion
      user.kycCompletionPercentage = Math.min(
        user.kycCompletionPercentage + 10,
        100,
      ); // Ensuring it doesn't exceed 100%
      await this.userRepository.save(user);

      this.logger.log(
        `Passport verification completed successfully for user ${user.id}`,
      );
      return user;
    } catch (error) {
      this.logger.error(
        `Error completing passport verification for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Error completing passport verification',
      );
    }
  }

  // Upload Signature
  async uploadSignature(
    user: User,
    file: Express.MulterS3.File,
  ): Promise<User> {
    try {
      const uploadedFile = await this.filesS3Service.create(file);

      if (!uploadedFile?.file?.path) {
        throw new InternalServerErrorException('File upload failed');
      }

      user.signatureImagePath = uploadedFile.file.path;
      user.signatureUploaded = true;
      user.kycCompletionPercentage = Math.min(
        user.kycCompletionPercentage + 10,
        100,
      );
      await this.userRepository.save(user);

      this.logger.log(`Signature uploaded successfully for user ${user.id}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Error uploading signature for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error uploading signature');
    }
  }

  // Politically Exposed Person (PEP) Information
  async updatePepDetails(user: User, dto: PepDto): Promise<User> {
    try {
      user.PEP = dto.PEP;
      user.PEPupdated = true;
      user.updatedAt = new Date();
      user.kycCompletionPercentage = Math.min(
        user.kycCompletionPercentage + 10,
        100,
      );
      await this.userRepository.save(user);

      this.logger.log(`PEP details updated for user ${user.id}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Error updating PEP details for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error updating PEP details');
    }
  }

  // Update Employment Details
  async updateEmploymentDetails(
    user: User,
    employmentDetails: EmploymentDetailsDto,
  ): Promise<User> {
    try {
      // Map employment details to the user entity
      Object.assign(user, {
        employmentStatus: employmentDetails.employmentStatus,
        companyName: employmentDetails.companyName,
        jobTitle: employmentDetails.jobTitle,
        companyEmail: employmentDetails.companyEmail,
        companyPhone: employmentDetails.companyPhone,
        incomeBand: employmentDetails.incomeBand,
        investmentSource: employmentDetails.investmentSource,
        otherInvestmentSource: employmentDetails.otherInvestmentSource,
        employmentDetailsProvided: true,
        kycCompletionPercentage: Math.min(
          user.kycCompletionPercentage + 10,
          100,
        ),
        updatedAt: new Date(),
      });

      await this.userRepository.save(user);

      this.logger.log(`Employment details updated for user ${user.id}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Error updating employment details for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Error updating employment details',
      );
    }
  }

  //update bank details
  // New method: Update Bank Details
  async updateBankDetails(
    user: User,
    bankDetails: BankDetailsDto,
  ): Promise<User> {
    try {
      const isValid = await this.smileService.verifyBankAccount(
        bankDetails.bankName,
        bankDetails.accountNumber,
      );

      if (!isValid) {
        throw new UnprocessableEntityException('Invalid account number');
      }

      Object.assign(user, {
        bankName: bankDetails.bankName,
        accountNumber: bankDetails.accountNumber,
        bankDetailsProvided: true,
        kycCompletionPercentage: Math.min(
          user.kycCompletionPercentage + 10,
          100,
        ),
        updatedAt: new Date(),
      });

      await this.userRepository.save(user);

      this.logger.log(`Bank details updated for user ${user.id}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Error updating bank details for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error updating bank details');
    }
  }

  //next of kin collection
  async updateNextOfkin(
    user: User,
    nextofkinDetailsdto: NextOfKinDto,
  ): Promise<User> {
    try {
      // Map employment details to the user entity
      Object.assign(user, {
        nextOfKinMiddlename: nextofkinDetailsdto.nextOfKinMiddlename,
        nextOfKinFirstname: nextofkinDetailsdto.nextOfKinFirstname,
        nextOfKinGender: nextofkinDetailsdto.nextOfKinGender,
        nextOfKinEmail: nextofkinDetailsdto.nextOfKinEmail,
        nextOfKinPhone: nextofkinDetailsdto.nextOfKinPhone,
        nextOfkinRelationship: nextofkinDetailsdto.nextofkinRelationship,
        otherNextOfKinRelationship:
          nextofkinDetailsdto.otherNextOfKinRelatioship,
        nextOfKinDetailsProvided: true,
        kycCompletionPercentage: Math.min(
          user.kycCompletionPercentage + 10,
          100,
        ),
        updatedAt: new Date(),
      });

      await this.userRepository.save(user);

      this.logger.log(`NextOFKin details updated for user ${user.id}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Error updating nextOfKin details for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException(
        'Error updating nextOfKin details',
      );
    }
  }

  // New method: Upload Address Proof
  async uploadAddressProof(
    user: User,
    file: Express.MulterS3.File,
    addressProofDto: AddressProofDto,
  ): Promise<User> {
    try {
      const uploadedFile = await this.filesS3Service.create(file);

      if (!uploadedFile?.file?.path) {
        throw new InternalServerErrorException('File upload failed');
      }

      // Validate document (implement this method)
      const isValid = await this.smileService.verifyAddressProof(
        addressProofDto.documentType,
        addressProofDto.documentType,
        uploadedFile.file.path,
      );

      if (!isValid) {
        throw new UnprocessableEntityException(
          'Invalid address proof document',
        );
      }

      Object.assign(user, {
        addressProofPath: uploadedFile.file.path,
        addressProofProvided: true,
        kycCompletionPercentage: Math.min(
          user.kycCompletionPercentage + 10,
          100,
        ),
        updatedAt: new Date(),
      });

      await this.userRepository.save(user);

      this.logger.log(`Address proof uploaded for user ${user.id}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Error uploading address proof for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error uploading address proof');
    }
  }

  // New method: Upload Government ID
  async uploadGovernmentId(
    user: User,
    governmentIdDto: GovernmentIdDto,
  ): Promise<User> {
    try {
      //   const uploadedFile = await this.filesS3Service.create(file);

      //   if (!uploadedFile?.file?.path) {
      //     throw new InternalServerErrorException('File upload failed');
      //   }

      // Validate ID (implement this method)
      const isValid = await this.smileService.verifyGovernmentId(
        governmentIdDto.idType,
        governmentIdDto.idNumber,
        governmentIdDto.expirationDate,
      );

      if (!isValid) {
        throw new UnprocessableEntityException('Invalid government ID');
      }

      Object.assign(user, {
        //governmentIdPath: uploadedFile.file.path,
        governmentIdType: governmentIdDto.idType,
        governmentIdProvided: true,
        kycCompletionPercentage: Math.min(
          user.kycCompletionPercentage + 10,
          100,
        ),
        updatedAt: new Date(),
      });

      await this.userRepository.save(user);

      this.logger.log(`Government ID uploaded for user ${user.id}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Error uploading government ID for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error uploading government ID');
    }
  }

  // New method: Update Tax Details
  async updateTaxDetails(
    user: User,
    taxDetails: TaxDetailsDto,
  ): Promise<User> {
    try {
      Object.assign(user, {
        taxLocation: taxDetails.taxLocation,
        taxIdentityNumber: taxDetails.taxIdentityNumber,
        taxDetailsProvided: true,
        kycCompletionPercentage: Math.min(
          user.kycCompletionPercentage + 10,
          100,
        ),
        updatedAt: new Date(),
      });

      await this.userRepository.save(user);

      this.logger.log(`Tax details updated for user ${user.id}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Error updating tax details for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error updating tax details');
    }
  }

  // New method: Get KYC Progress
  async getKycProgress(
    user: User,
  ): Promise<{ percentage: number; completedSteps: string[] }> {
    try {
      const completedSteps: string[] = [];
      if (user.userRegisteredAndVerified)
        completedSteps.push('User Registered And Verified');
      if (user.passportPhotographVerificationInitiated)
        completedSteps.push('Passport Verification');
      if (user.signatureUploaded) completedSteps.push('Signature Upload');
      if (user.PEPupdated) completedSteps.push('PEP Details');
      if (user.employmentDetailsProvided)
        completedSteps.push('Employment Details');
      if (user.nextOfKinDetailsProvided)
        completedSteps.push('Next of Kin Details');
      if (user.bankDetailsProvided) completedSteps.push('Bank Details');
      if (user.addressProofProvided) completedSteps.push('Address Proof');
      if (user.governmentIdProvided) completedSteps.push('Government ID');
      if (user.taxDetailsProvided) completedSteps.push('Tax Details');

      return {
        percentage: user.kycCompletionPercentage,
        completedSteps,
      };
    } catch (error) {
      this.logger.error(
        `Error fetching KYC progress for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error fetching KYC progress');
    }
  }
}
