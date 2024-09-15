import { ApiProperty } from "@nestjs/swagger";
import { IsCreditCard, IsString } from "class-validator";

export class WalletWithdrawalDto{
    @ApiProperty({type:String})
    @IsString()
    accountNumber:string

    @ApiProperty({type:String})
    @IsString()
    bankName:string

    @ApiProperty({type:Number})
    @IsString()
    amount:number


}

export class WalletFundingDto{
    @ApiProperty({type:Number})
    @IsString()
    amount:number
   
}

export class CardDetailsDto{
    @ApiProperty({type:String})
    @IsCreditCard()
    cardDigits:string
}