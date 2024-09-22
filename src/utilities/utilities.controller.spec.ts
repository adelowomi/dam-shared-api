import { Test, TestingModule } from '@nestjs/testing';
import { UtilitiesController } from './utilities.controller';
import { UtilitiesService } from './utilities.service';
import { PayStackService } from '../utils/services/paystack.service';
import { FetchModule } from 'nestjs-fetch';
import { CustomFetchModule } from '../utils/modules/customFetch.module.';
import { ResponseService } from '../utils/services/response.service';

describe('UtilitiesController', () => {
  let controller: UtilitiesController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [FetchModule, CustomFetchModule],
      providers: [UtilitiesService, PayStackService, ResponseService],
      controllers: [UtilitiesController],
    }).compile();

    controller = module.get<UtilitiesController>(UtilitiesController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
