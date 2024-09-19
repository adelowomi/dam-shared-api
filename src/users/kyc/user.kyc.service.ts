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
import {
  ResponseService,
  StandardResponse,
} from '../../utils/services/response.service';

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
    private responseService: ResponseService,
  ) {}

  private async updateKycStatus(
    user: UserEntity,
    status: KycUpdates,
  ): Promise<void> {
    if (!user.kycCompletionStatus) {
      user.kycCompletionStatus = {} as { [key in KycUpdates]: boolean };
    }
    user.kycCompletionStatus[status] = true;
    user.updatedAt = new Date();
    await this.userRepository.save(user);
  }

 

  async getKycProgress(user: UserEntity): Promise<StandardResponse<number>> {
    try {
      const totalSteps = Object.keys(KycUpdates).length;
      const completedSteps = Object.values(
        user.kycCompletionStatus || {},
      ).filter(Boolean).length;

      const percentage = Math.round((completedSteps / totalSteps) * 100);

      return this.responseService.success(
        'kyc Progress returned succssfully',
        percentage,
      );
    } catch (error) {
      return this.responseService.internalServerError(
        'Error returning Kyc Progress',
        error,
      );
    }
  }
  private async updateUser(userId: number, updateData: Partial<UserEntity>): Promise<UserEntity | null> {
    const existingUser = await this.userRepository.findOne({ where: { id: userId } });
    console.log("🚀 ~ KycService ~ updateUser ~ existingUser:", existingUser)
  
    if (!existingUser) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }
  
    // Merge existing data with the new update data
    const updatedUser = { ...existingUser, ...updateData };
    console.log("🚀 ~ KycService ~ updateUser ~ updatedUser:", updatedUser)
    
    return await this.userRepository.save(updatedUser);
  
    
  }

  private async updateUser1(userId: number, updateData: Partial<UserEntity>): Promise<UserEntity|null> {
    await this.userRepository.update(userId, updateData);
    return this.userRepository.findOne({ where: { id: userId } });
  }
  
  

  // Passport Photograph Verification Initiation

  async identifyID(user: UserEntity, dto: NigerianIdDto): Promise<StandardResponse<any>> {
    try {
      console.log('this line was passed ');
      let idType: string;
      let idNumber: string;

      switch (dto.idType) {
        case NigerianIdEnum.BVN:
          idType = 'BVN';
          idNumber = dto.bvn!;
          console.log('🚀 ~ KycService ~ identifyID ~ idNumber:', idNumber);

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
          return this.responseService.badRequest('Invalid ID type provided');
      }

      if (!idNumber) {
        return this.responseService.badRequest(
          `No ${idType} provided for verification`,
        );
      }

      const response = await this.smileService.performIdVerification(
        user.id.toString(),
        idType,
        idNumber,
        user.firstName,
        user.lastName,
        user.DOB,
        user.phoneNumber,
      );  
      console.log('🚀 ~ KycService ~ identifyID ~ response:', response);

      const updatedUser = await this.updateUser(user.id, {
        updatedAt: new Date()
      });
      await this.updateKycStatus(user, KycUpdates.PEPupdated);

     

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have initiated the KYC process for your ${idType}.`,
        subject: 'KYC phase initialization after registration',
        account: user.id,
      });

      this.logger.log(
        `ID verification (${idType}) initiated for user ${user.id}`,
      );

      return this.responseService.success(
        'id verficication initiated successfuly',
        { response },
      );
    } catch (error) {
      this.logger.error(
        `Failed to initiate ID verification for user ${user.id}`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error initiating ID verification',
        { error: error },
      );
    }
  }

  async submitSelfieJob(
    user: UserEntity,
    base64Selfie: string,
    libraryVersion: string,
  ): Promise<StandardResponse<any>> {
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
        libraryVersion,
      );

      console.log('Selfie job submitted:', response);


        const updatedUser = await this.updateUser(user.id, {
        updatedAt: new Date()
      });
      await this.updateKycStatus(user, KycUpdates.selfieVerificationInitiated);

      // Send a notification to the user about the initiation of the selfie KYC process
      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have initiated the selfie KYC process.`,
        subject: 'Selfie KYC Initiation',
        account: user.id,
      });

      // Log the successful initiation of the process
      console.log(`Selfie KYC process initiated for user ${user.id}`);

      // Return the result of the selfie job submission
      return this.responseService.success(
        'smart selfie successfully initiated',
        { response },
      );

    } catch (error) {
      console.error('Failed to submit selfie for verification:', error.stack);
      return this.responseService.Response(
        false,
        'Error initializing smart selfie',
        HttpStatus.INTERNAL_SERVER_ERROR,
        error,
      );
    }
  }

  async confirmSignatureUpload(
    user: UserEntity,
    file: Express.Multer.File,
  ): Promise<StandardResponse<UserEntity>> {
    try {
      const fileUploadDto = {
        fileName: file.originalname,
        fileSize: file.size,
      };

      // Upload file using FilesS3PresignedService
      const { file: uploadedFile, uploadSignedUrl } =
        await this.filesS3PresignedService.create(fileUploadDto);


      
        user.signatureImagePath=uploadSignedUrl,
        user.updatedAt= new Date()
      
      await this.updateKycStatus(user, KycUpdates.signatureUploaded);

      await this.userRepository.save(user)


      // Send a notification about the update
      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully uploaded your signature.`,
        subject: 'KYC phase 3',
        account: user.id,
      });

      return this.responseService.success(
        'signature uploaded successfully',
        user,
      );
    } catch (error) {
      this.logger.error(
        `Error confirming signature upload for user ${user.id}`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error uploading signature',
        error,
      );
    }
  }

  // Politically Exposed Person (PEP) Information
  async updatePepDetails(
    user: UserEntity,
    dto: PepDto,
  ): Promise<StandardResponse<UserEntity>> {
    console.log("🚀 ~ KycService ~ user:", user)
    try {
     

       await this.updateUser(user.id,{
        PEP:dto.PEP,
        kycCompletionStatus : { ...user.kycCompletionStatus, 'PEPupdated': true },
        updatedAt:new Date()

       })
       

      // Send a notification about the update
      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated a PEP detail.`,
        subject: 'KYC phase 3',
        account: user.id,
      });

      // Log success
      //this.logger.log(`PEP details updated for user ${user.id}`);
      return this.responseService.success(
        'pep details updated successfully',
        user,
      );
    } catch (error) {
      // Log and throw error if something goes wrong
      this.logger.error(
        `Error updating PEP details for user ${user.id}`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error updating PEP details',
        error,
      );
    }
  }

  // Update Employment Details
  async updateEmploymentDetails(
    user: UserEntity,
    employmentDetails: EmploymentDetailsDto,
  ): Promise<StandardResponse<UserEntity>> {
    try {
      // Map employment details to the user entity

      await this.updateUser(user.id, {
        employmentStatus:employmentDetails.employmentStatus,
        companyName:employmentDetails.companyName,
        jobTitle:employmentDetails.jobTitle,
        companyEmail:employmentDetails.companyEmail,
        companyPhone:employmentDetails.companyPhone,
        incomeBand:employmentDetails.incomeBand,
        investmentSource:employmentDetails.investmentSource,
        otherInvestmentSource:employmentDetails.otherInvestmentSource,
        kycCompletionStatus : { ...user.kycCompletionStatus, 'employmentDetailsProvided': true },
        updatedAt: new Date()
      });
      
    

      // Send notification about employment details update
      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated your employment details.`,
        subject: 'KYC phase 4',
        account: user.id,
      });

      // Log success
      this.logger.log(`Employment details updated for user ${user.id}`);
      return this.responseService.success(
        'employment details updated successfully',
        user,
      );
    } catch (error) {
      // Log error and rethrow exception
      this.logger.error(
        `Error updating employment details for user ${user.id}`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error updating Employment Details',
        error,
      );
    }
  }

  // New method: Update Bank Details
  async updateBankDetails(
    user: UserEntity,
    bankDetails: BankDetailsDto,
  ): Promise<StandardResponse<UserEntity>> {
    try {
      const isValid = await this.smileService.performBankVerification(
        user.id.toString(),
        bankDetails.accountNumber,
        bankDetails.bankcode,
      );

      if (!isValid) {
        return this.responseService.badRequest('Invalid account number');
      }

     

      await this.updateUser(user.id, {
        accountNumber:bankDetails.accountNumber,
        bankVerified:true,
        kycCompletionStatus : { ...user.kycCompletionStatus, 'bankDetailsProvided': true },
        updatedAt: new Date()
      });
     


      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated your bank details.`,
        subject: 'KYC phase 5',
        account: user.id,
      });

      this.logger.log(`Bank details updated for user ${user.id}`);
      return this.responseService.success(
        'bank details updated successfully',
        user,
      );
    } catch (error) {
      this.logger.error(
        `Error updating bank details for user ${user.id}`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error updating bank details for user',
        error,
      );
    }
  }

  //next of kin collection
  async updateNextOfkin(
    user: UserEntity,
    nextofkinDetailsdto: NextOfKinDto,
  ): Promise<StandardResponse<UserEntity>> {
    console.log("🚀 ~ KycService ~ user:", user)
    try {
      // Map employment details to the user entity
  


      await this.updateUser(user.id, {
        nextOfKinMiddlename:nextofkinDetailsdto.nextOfKinMiddlename,
        nextOfKinFirstname:nextofkinDetailsdto.nextOfKinFirstname,
        nextOfKinGender:nextofkinDetailsdto.nextOfKinGender,
        nextOfKinLastname:nextofkinDetailsdto.nextOfKinLastname,
        nextOfKinEmail:nextofkinDetailsdto.nextOfKinEmail,
        nextOfKinPhone:nextofkinDetailsdto.nextOfKinPhone,
        nextOfkinRelationship:nextofkinDetailsdto.nextofkinRelationship,
        kycCompletionStatus : { ...user.kycCompletionStatus, 'nextOfKinDetailsProvided': true },
        updatedAt: new Date()
      });
     



      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated next of kin details.`,
        subject: 'KYC phase 6',
        account: user.id,
      });

      this.logger.log(`NextOFKin details updated for user ${user.id}`);
      return this.responseService.success(
        'next of kin details updated successfully',
        user,
      );
    } catch (error) {
      this.logger.error(
        `Error updating nextOfKin details for user ${user.id}`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error Updating nextOfKin details',
        error,
      );
    }
  }

  // New method: Upload Address Proof
  async uploadAddressProof(
    user: UserEntity,
    file: Express.Multer.File,
  ): Promise<StandardResponse<UserEntity>> {
    try {
      const fileUploadDto = {
        fileName: file.originalname,
        fileSize: file.size,
      };

      // Upload file using FilesS3PresignedService
      const { file: uploadedFile, uploadSignedUrl } =
        await this.filesS3PresignedService.create(fileUploadDto);


       await this.updateUser(user.id, {
        addressProofPath:uploadSignedUrl,
        kycCompletionStatus : { ...user.kycCompletionStatus, 'addressProofProvided': true },
        updatedAt: new Date()
      });
      

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully uploaded address proof.`,
        subject: 'KYC phase 7 ',
        account: user.id,
      });

      this.logger.log(`Address proof uploaded for user ${user.id}`);
      return this.responseService.success(
        'address proof uploaded successfully',
        user,
      );
    } catch (error) {
      this.logger.error(
        `Error uploading address proof for user ${user.id}`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error uploading address proof',
        error,
      );
    }
  }

  // New method: Update Tax Details
  async updateTaxDetails(
    user: UserEntity,
    taxDetails: TaxDetailsDto,
  ): Promise<StandardResponse<UserEntity>> {
    try {
     


      await this.updateUser(user.id, {
        taxLocation:taxDetails.taxLocation,
        taxIdentityNumber:taxDetails.taxIdentityNumber,
        kycCompletionStatus : { ...user.kycCompletionStatus, 'taxDetailsProvided': true },
        updatedAt: new Date()
      });
      
     

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully updated tax details.`,
        subject: 'KYC phase 9',
        account: user.id,
      });

      this.logger.log(`Tax details updated for user ${user.id}`);
      return this.responseService.success(
        'Tax  details updated successfully',
        user,
      );
    } catch (error) {
      this.logger.error(
        `Error updating tax details for user ${user.id}`,
        error.stack,
      );
      return this.responseService.internalServerError(
        'Error updating Tax Details',
        error,
      );
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
