import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiCreatedResponse, ApiTags } from '@nestjs/swagger';
import { WalletService } from './wallet.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../roles/roles.guard';
import {
  CardDetailsDto,
  WalletFundingDto,
  WalletWithdrawalDto,
} from '../dto/wallet.dto';
import { StandardResponse } from '../../utils/services/response.service';
import { CardEntity } from '../infrastructure/persistence/relational/entities/card.entity';
import { WalletEntity } from '../infrastructure/persistence/relational/entities/wallet.entity';

@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'), RolesGuard)
@ApiTags('WALLET')
@Controller({ path: 'wallet', version: '1' })
export class WalletController {
  constructor(private readonly walletservice: WalletService) {}

  @Post('fund-account')
  async fundAccount(
    @Body() dto: WalletFundingDto,
    @Req() req,
  ): Promise<StandardResponse<WalletEntity>> {
    return await this.walletservice.fundAccount(req.user, dto);
  }

  @Post('withdraw-funds')
  async withdraw(
    @Body() dto: WalletWithdrawalDto,
    @Req() req,
  ): Promise<StandardResponse<WalletEntity>> {
    return await this.walletservice.withdraw(req.user, dto);
  }

  @Post('add-card')
  async addCard(
    @Body() dto: CardDetailsDto,
    @Req() req,
  ): Promise<StandardResponse<CardEntity>> {
    return await this.walletservice.addCard(req.user, dto);
  }

  @Delete('remove-card/:cardID')
  async removeCard(
    @Req() req,
    @Param('cardID') cardID: number,
  ): Promise<StandardResponse<boolean>> {
    return await this.walletservice.removeCard(req.user, cardID);
  }

  @Get('fetch-wallet-balance')
  async getWalletBalance(@Req() req): Promise<StandardResponse<number>> {
    return await this.walletservice.getWalletBalance(req.user);
  }

  @Get('get-saved-cards')
  async getSavedCards(@Req() req): Promise<StandardResponse<CardEntity[]>> {
    return await this.walletservice.getSavedCards(req.user);
  }
}
