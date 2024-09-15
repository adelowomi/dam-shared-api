import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Post, Req, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiCreatedResponse, ApiTags } from '@nestjs/swagger';
import { WalletService } from "./wallet.service";
import { AuthGuard } from "@nestjs/passport";
import { RolesGuard } from "../../roles/roles.guard";
import { CardDetailsDto, WalletFundingDto, WalletWithdrawalDto } from "../dto/wallet.dto";

@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'), RolesGuard)
@ApiTags('WALLET')
@Controller({path:'wallet',version:'1'})
export class WalletController{
    constructor(private readonly walletservice:WalletService){}

    @Post('fund-account')
    @HttpCode(HttpStatus.OK)
    async fundAccount(@Body()dto:WalletFundingDto,@Req()req){
        return await this.walletservice.fundAccount(req.user,dto)
        
    }

    @Post('withdraw-funds')
    @HttpCode(HttpStatus.OK)
    async withdraw(@Body()dto:WalletWithdrawalDto,@Req()req){
        return await this.walletservice.withdraw(req.user,dto)
        
    }

    @Post('add-card')
    @HttpCode(HttpStatus.OK)
    async addCard(@Body()dto:CardDetailsDto,@Req()req){
        return await this.walletservice.addCard(req.user,dto)
        
    }

    @Delete('remove-card/:cardID')
    @HttpCode(HttpStatus.NO_CONTENT)
    async removeCard(@Req()req,@Param('cardID')cardID:number){
        return await this.walletservice.removeCard(req.user,cardID)
        
    }

    @Get('fetch-wallet-balance')
    @HttpCode(HttpStatus.OK)
    async getWalletBalance(@Req()req){
        return await this.walletservice.getWalletBalance(req.user)
        
    }

    @Get('get-saved-cards')
    @HttpCode(HttpStatus.OK)
    async getSavedCards(@Req()req){
        return await this.walletservice.getSavedCards(req.user)
        
    }


}