import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource, QueryRunner } from 'typeorm';
import { Mailer } from '../../mail/mail.service';
import { WalletEntity } from '../infrastructure/persistence/relational/entities/wallet.entity';
import { UserEntity } from '../infrastructure/persistence/relational/entities/user.entity';
import {
  TransactionEntity,
  TransactionStatus,
  Transactiontype,
} from '../infrastructure/persistence/relational/entities/transactions.entity';
import { CardEntity } from '../infrastructure/persistence/relational/entities/card.entity';
import { User } from '../domain/user';
import { PaymentGatewayService } from '../../payment/payment.service';
import { SmileService } from '../../utils/services/smileID.service';
import { CardDetailsDto, WalletFundingDto, WalletWithdrawalDto } from '../dto/wallet.dto';
import { NotificationsService } from '../../notifications/notifications.service';
import { ResponseService, StandardResponse } from '../../utils/services/response.service';

@Injectable()
export class WalletService {
  constructor(
    @InjectDataSource() private dataSource: DataSource,
    private paymentGatewayService: PaymentGatewayService,
    private emailService: Mailer,
    private bankAccountValidationService: SmileService,
    private notificationService:NotificationsService,
    private responseService: ResponseService,
  ) {}

  async fundAccount(
    user: UserEntity,
    dto:WalletFundingDto
  ): Promise<StandardResponse<WalletEntity>> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const wallet = await queryRunner.manager.findOne(WalletEntity, {
        where: { owner: user },
      });
      if (!wallet) {
        return this.responseService.notFound('Wallet not found');
      }

      // Process payment through payment gateway
      const paymentResult = await this.paymentGatewayService.processPayment(
        dto.amount
       
      );
      if (!paymentResult.success) {
        return this.responseService.badRequest('Payment failed');
      }

      // Update wallet balance
      wallet.balance += dto.amount;
      wallet.lastDepositAt = new Date();
      await queryRunner.manager.save(wallet);

      // Create transaction record
      const transaction = new TransactionEntity();
      transaction.user = user;
      transaction.amount = dto.amount;
      transaction.type = Transactiontype.FUNDING;
      transaction.status = TransactionStatus.SUCCESS;
      await queryRunner.manager.save(transaction);

      await queryRunner.commitTransaction();

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully funded your account.`,
        subject: 'Account Funding',
        account: user.id,
      });

      // Send confirmation email
      await this.emailService.sendFundingConfirmation(user.email, dto.amount);

      return this.responseService.success('wallet funded',wallet);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      return this.responseService.internalServerError('Error funding wallet',error);
    } finally {
      await queryRunner.release();
    }
  }

  async addCard(user: UserEntity, carddto:CardDetailsDto): Promise<StandardResponse<CardEntity>> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Tokenize card details (implement this method in PaymentGatewayService)
      const tokenizedCard =
        await this.paymentGatewayService.tokenizeCard(carddto.cardDigits);

      const card = new CardEntity();
      card.user = user;
      card.token = tokenizedCard.token;
      card.last4Digits = tokenizedCard.last4Digits;
      card.expiryMonth = tokenizedCard.expiryMonth;
      card.expiryYear = tokenizedCard.expiryYear;
      card.cardType = tokenizedCard.cardType;
      card.addedAt = new Date()
      

      await queryRunner.manager.save(card);

      await queryRunner.commitTransaction();

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully added a card.`,
        subject: 'Card Added To Account',
        account: user.id,
      });

      // Notify user
      await this.emailService.sendCardAddedNotification(user.email,card.cardType,card.last4Digits,card.expiryMonth,card.expiryYear);

      return this.responseService.success('card added successfully',card);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      return this.responseService.internalServerError('Error in adding card',error);
    } finally {
      await queryRunner.release();
    }
  }

  async removeCard(user: UserEntity, cardId: number): Promise<StandardResponse<boolean>> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const card = await queryRunner.manager.findOne(CardEntity, {
        where: { id: cardId, user: { id: user.id } },
      });
      if (!card) {
        return this.responseService.notFound('Card not found');
      }

      await queryRunner.manager.remove(card);

      await queryRunner.commitTransaction();

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully removed a card from your account.`,
        subject: 'Card Removed From Account',
        account: user.id,
      });

      // Notify user
      await this.emailService.sendCardRemovedNotification(user.email,card.cardType,card.last4Digits);
      return this.responseService.success('wallet deleted successfully',true)
    } catch (error) {
      await queryRunner.rollbackTransaction();
      return this.responseService.internalServerError('Error removing card',error);
    } finally {
      await queryRunner.release();
    }
  }

  async withdraw(
    user: UserEntity,
    dto:WalletWithdrawalDto,
  ): Promise<StandardResponse<WalletEntity>> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const wallet = await queryRunner.manager.findOne(WalletEntity, {
        where: { owner: { id: user.id } },
      });
      if (!wallet) {
        return this.responseService.notFound('Wallet not found');
      }

      if (wallet.balance < dto.amount) {
        return this.responseService.badRequest('Insufficient funds');
      }

      // Validate bank account
      // const isValidBankAccount =
      //   await this.bankAccountValidationService.verifyBankAccount(dto.accountNumber,dto.bankName)
      //   ;
      // if (!isValidBankAccount) {
      //   throw new BadRequestException('Invalid bank account details');
      // }

      // Process withdrawal through payment gateway
      const withdrawalResult =
        await this.paymentGatewayService.processWithdrawal(
          dto.amount,
          dto.accountNumber
         
        );
      if (!withdrawalResult.success) {
        throw new BadRequestException('Withdrawal failed');
      }

      // Update wallet balance
      wallet.balance -= dto.amount;
      wallet.lastwithdrawalAt = new Date();
      await queryRunner.manager.save(wallet);

      // Create transaction record
      const transaction = new TransactionEntity();
      transaction.user = user;
      transaction.amount = dto.amount;
      transaction.type = Transactiontype.WITHDRAWAL;
      transaction.status = TransactionStatus.SUCCESS;
      await queryRunner.manager.save(transaction);

      await queryRunner.commitTransaction();

      await this.notificationService.create({
        message: `Hello ${user.firstName}, you have successfully withdrawn from your account.`,
        subject: 'Account Fund Withdrawal',
        account: user.id,
      });

      // Send confirmation email
      await this.emailService.sendWithdrawalConfirmation(user.email, dto.amount);

      return this.responseService.success('funds withdrawal succesful',wallet);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      return this.responseService.internalServerError('Error withdrawing from wallet',error);
    } finally {
      await queryRunner.release();
    }
  }

  async getWalletBalance(user: UserEntity): Promise<StandardResponse<number>> {
    const wallet = await this.dataSource
      .getRepository(WalletEntity)
      .findOne({ where: { owner: { id: user.id } } });
    if (!wallet) {
      return this.responseService.notFound('Wallet not found');
    }
    const balance = wallet.balance;
    return this.responseService.success('wallet balance fetched successfully',balance)
  }

  async getSavedCards(user: UserEntity): Promise<StandardResponse<CardEntity[]>> {
    const cards= await this.dataSource
      .getRepository(CardEntity)
      .find({ where: { user: { id: user.id } } });

      return this.responseService.success('saved cards fetched',cards)
  }
}
