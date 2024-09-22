// @ts-no-check

import { Module, Global } from '@nestjs/common';
import { CustomFetchService } from '../services/CustomFetchService';
import { FetchModule } from 'nestjs-fetch';

@Global()
@Module({
  imports: [FetchModule],
  providers: [CustomFetchService],
  exports: [CustomFetchService],
})
export class CustomFetchModule {}
