import { Test, TestingModule } from '@nestjs/testing';
import { UtilitiesService } from './utilities.service';
import { PayStackService } from '../utils/services/paystack.service';
import { ResponseService } from '../utils/services/response.service';
import { FetchModule } from 'nestjs-fetch';
import { CustomFetchModule } from '../utils/modules/customFetch.module.';

describe('UtilitiesService', () => {
  let service: UtilitiesService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [FetchModule, CustomFetchModule],
      providers: [UtilitiesService, PayStackService, ResponseService],
    }).compile();

    service = module.get<UtilitiesService>(UtilitiesService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
