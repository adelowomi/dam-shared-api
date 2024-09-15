import { Module } from "@nestjs/common";
import { PaymentGatewayService } from "./payment.service";

@Module({
    providers:[PaymentGatewayService],
    exports:[PaymentGatewayService]
})
export class PaymentGatewayModule{}