import { Module } from '@nestjs/common';
import { UtilitiesService } from './utilities.service';
import { UtilitiesController } from './utilities.controller';
import { PayStackService } from '../utils/services/paystack.service';
import { ResponseService } from '../utils/services/response.service';
import { FetchModule } from 'nestjs-fetch';

@Module({
  imports: [FetchModule],
  controllers: [UtilitiesController],
  providers: [UtilitiesService, PayStackService, ResponseService],
})
export class UtilitiesModule {}
