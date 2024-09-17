import {
  Injectable,
  HttpStatus,
  UnprocessableEntityException,
  NotFoundException,
  InternalServerErrorException,
  Logger,
  BadRequestException,
  PayloadTooLargeException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotificationsService } from '../../notifications/notifications.service';
import { ZanzibarService } from '../../utils/services/zanibar.service';
import { SmileService } from '../../utils/services/smileID.service';
import { FilesS3Service } from '../../files/infrastructure/uploader/s3/files.service';
import { UserEntity } from '../infrastructure/persistence/relational/entities/user.entity';
import { PepDto } from '../dto/KEP.dto';
import { EmploymentDetailsDto } from '../dto/employment-details.dto';
import { NextOfKinDto } from '../dto/next-of-kin.dto';
import { BankDetailsDto } from '../dto/bankdetails.dto';
import { AddressProofDto } from '../dto/address-proof.dto';
import { GovernmentIdDto } from '../dto/goverenment-id.dto';
import { TaxDetailsDto } from '../dto/tax-details.dto';
import { User } from '../domain/user';
import { NigerianIdDto, NigerianIdEnum } from '../dto/nigerianid.dto';
import { v4 as uuidv4 } from 'uuid';
import { FileUploadDto } from '../../files/infrastructure/uploader/s3-presigned/dto/file.dto';
import { FilesS3PresignedService } from '../../files/infrastructure/uploader/s3-presigned/files.service';
import { KycUpdates } from './kyc.enum';

@Injectable()
export class KycService {
  private readonly logger = new Logger(KycService.name);

  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private notificationService: NotificationsService,
    private readonly zanibarService: ZanzibarService,
    private readonly smileService: SmileService,
    private readonly filesS3PresignedService: FilesS3PresignedService,
  ) {}

  private async updateKycStatus(user: UserEntity, status: KycUpdates): Promise<void> {
    if (!user.kycCompletionStatus) {
      user.kycCompletionStatus = {} as { [key in KycUpdates]: boolean };
    }
    user.kycCompletionStatus[status] = true;
    user.updatedAt = new Date();
    await this.userRepository.save(user);
  }

  async getKycProgress(user: UserEntity): Promise<number> {
   

    const totalSteps = Object.keys(KycUpdates).length;
    const completedSteps = Object.values(user.kycCompletionStatus || {}).filter(Boolean).length;
    
    return Math.round((completedSteps / totalSteps) * 100);
  }


 

  // Passport Photograph Verification Initiation

  async identifyID(user: UserEntity, dto: NigerianIdDto): Promise<string> {
    try {
      console.log('this line was passed ')
      let idType: string;
      let idNumber: string;

      switch (dto.idType) {
        case NigerianIdEnum.BVN:
          idType = 'BVN';
          idNumber = dto.bvn!;
          console.log("🚀 ~ KycService ~ identifyID ~ idNumber:", idNumber)
          
          break;
        case NigerianIdEnum.NIN_V2:
          idType = 'NIN_V2';
          idNumber = dto.nin_v2!;
          break;
        case NigerianIdEnum.NIN:
          idType = 'NIN_SLIP';
          idNumber = dto.nin_slip!;
          break;
        case NigerianIdEnum.PHONE_NUMBER:
          idType = 'PHONE_NUMBER';
          idNumber = dto.phone_number!;
          break;
        case NigerianIdEnum.VOTER_ID:
          idType = 'VOTER_ID';
          idNumber = dto.voter_id!;
          break;
        default:
          throw new BadRequestException('Invalid ID type provided');
      }

      if (!idNumber) {
        throw new BadRequestException(`No ${idType} provided for verification`);
      }

      const response = await this.smileService.performIdVerification(
        user.id.toString(),
        idType,
        idNumber,
        user.firstName,
        user.lastName,
        user.DOB,
        user.phoneNumber
      );
      console.log("🚀 ~ KycService ~ identifyID ~ response:", response)

      await this.updateKycStatus(user, KycUpdates.governmentIdProvided);
      await this.userRepository.save(user);

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have initiated the KYC process for your ${idType}.`,
        subject: 'KYC phase initialization after registration',
        account: user.id,
      });

      this.logger.log(`ID verification (${idType}) initiated for user ${user.id}`);

      return response;
    } catch (error) {
      this.logger.error(
        `Failed to initiate ID verification for user ${user.id}`,
        error.stack
      );
      throw new InternalServerErrorException(
        'Failed to initiate identity verification process'
      );
    }
  }

  async submitSelfieJob(user: UserEntity, base64Selfie: string, libraryVersion: string): Promise<string> {
    try {
      console.log('Submitting selfie for verification...');
  
      const images = [
        {
          image_type_id: 0, // Image type 0 corresponds to a selfie
          image: base64Selfie, // Base64-encoded selfie image
        },
      ];
  
      // Submit the selfie for KYC verification
      const response = await this.smileService.submitSelfieJob(
       user.id.toString(),
        images,
        libraryVersion
      );
  
      console.log('Selfie job submitted:', response);
  
      // Update user entity to reflect that the selfie verification was initiated
      await this.updateKycStatus(user, KycUpdates.selfieVerificationInitiated);
      await this.userRepository.save(user);// This assumes you have such a field in your entity
      
  
      // Send a notification to the user about the initiation of the selfie KYC process
      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have initiated the selfie KYC process.`,
        subject: 'Selfie KYC Initiation',
        account: user.id,
      });
  
      // Log the successful initiation of the process
      console.log(`Selfie KYC process initiated for user ${user.id}`);
  
      // Return the result of the selfie job submission
      return response;
  
    } catch (error) {
      console.error('Failed to submit selfie for verification:', error.stack);
      throw new InternalServerErrorException('Failed to submit selfie for KYC verification');
    }
  }
  


  async confirmSignatureUpload(
    user: UserEntity,
    file: Express.Multer.File,
  ): Promise<any> {
    try {
      const fileUploadDto = {
        fileName: file.originalname,
        fileSize: file.size,
      };

      // Upload file using FilesS3PresignedService
      const { file: uploadedFile, uploadSignedUrl } = await this.filesS3PresignedService.create(fileUploadDto);

      // Update user's signature image path
      user.signatureImagePath = uploadSignedUrl;
      await this.updateKycStatus(user, KycUpdates.signatureUploaded);
      await this.userRepository.save(user);

      // Send a notification about the update
      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully uploaded your signature.`,
        subject: 'KYC phase 3',
        account: user.id,
      });


      return { message: 'Your signature has been uploaded successfully.' };
    } catch (error) {
      this.logger.error(
        `Error confirming signature upload for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error confirming signature upload');
    }
  }


  // Politically Exposed Person (PEP) Information
  async updatePepDetails(user: UserEntity, dto: PepDto): Promise<UserEntity> {
    try {
      // Update PEP details
      user.PEP = dto.PEP;
      user.updatedAt = new Date();
      await this.updateKycStatus(user, KycUpdates.PEPupdated);
  
      
      // Save updated user details
      await this.userRepository.save(user);
  
      // Send a notification about the update
      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated a PEP detail.`,
        subject: 'KYC phase 3',
        account: user.id,
      });
  
      // Log success
      this.logger.log(`PEP details updated for user ${user.id}`);
      return user;
    } catch (error) {
      // Log and throw error if something goes wrong
      this.logger.error(
        `Error updating PEP details for user ${user.id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Error updating PEP details');
    }
  }
  

  // Update Employment Details
  async updateEmploymentDetails(
    user: UserEntity,
    employmentDetails: EmploymentDetailsDto,
  ): Promise<UserEntity> {
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
      });
     
      user.updatedAt = new Date();
      await this.updateKycStatus(user, KycUpdates.EemploymentDetailsProvided);
  
      // Save updated user data
      await this.userRepository.save(user);
  
      // Send notification about employment details update
      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated your employment details.`,
        subject: 'KYC phase 4',
        account: user.id,
      });
  
      // Log success
      this.logger.log(`Employment details updated for user ${user.id}`);
      return user;
    } catch (error) {
      // Log error and rethrow exception
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
    user: UserEntity,
    bankDetails: BankDetailsDto,
  ): Promise<UserEntity> {
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
      });
      
      user.updatedAt = new Date();
      await this.updateKycStatus(user, KycUpdates.bankDetailsProvided);

      await this.userRepository.save(user);

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated your bank details.`,
        subject: 'KYC phase 5',
        account: user.id,
      });

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
    user: UserEntity,
    nextofkinDetailsdto: NextOfKinDto,
  ): Promise<UserEntity> {
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
       
      });

      
      user.updatedAt = new Date();
      await this.updateKycStatus(user, KycUpdates.nextOfKinDetailsProvided);

      await this.userRepository.save(user);

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated next of kin details.`,
        subject: 'KYC phase 6',
        account: user.id,
      });

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
    user: UserEntity,
    file: Express.Multer.File,
   
  ): Promise<UserEntity> {
    try {
      
      const fileUploadDto = {
        fileName: file.originalname,
        fileSize: file.size,
      };

      // Upload file using FilesS3PresignedService
      const { file: uploadedFile, uploadSignedUrl } = await this.filesS3PresignedService.create(fileUploadDto);

     
      user.addressProofPath = uploadSignedUrl
      user.updatedAt = new Date();
      await this.updateKycStatus(user, KycUpdates.addressProofProvided);
      await this.userRepository.save(user);

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully uploaded address proof.`,
        subject: 'KYC phase 7 ',
        account: user.id,
      });

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

 

  // New method: Update Tax Details
  async updateTaxDetails(user: UserEntity, taxDetails: TaxDetailsDto): Promise<UserEntity> {
    try {
      Object.assign(user, {
        taxLocation: taxDetails.taxLocation,
        taxIdentityNumber: taxDetails.taxIdentityNumber,
      });

     
      user.updatedAt = new Date();
      await this.updateKycStatus(user, KycUpdates.taxDetailsProvided);

      await this.userRepository.save(user);

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated tax details.`,
        subject: 'KYC phase 9',
        account: user.id,
      });

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
  

  async UpdateKycStatus(userId: number, isVerified: boolean): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new Error('User not found');
    }

    //user.passportPhotographVerificationInitiated = isVerified; // Assuming you have a column like this in your User entity
    await this.userRepository.save(user);
  }
}
