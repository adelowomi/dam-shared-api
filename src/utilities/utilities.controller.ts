import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { UtilitiesService } from './utilities.service';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiTags,
  getSchemaPath,
} from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { PayStackBank } from '../utils/services/models/PayStaackStandardResponse';
import { StandardResponse } from '../utils/services/response.service';

@ApiTags('Utilities')
@Controller('utilities')
export class UtilitiesController {
  constructor(private readonly utilitiesService: UtilitiesService) {}

  @Get('banks')
  @ApiBearerAuth()
  @Get('me')
  @UseGuards(AuthGuard('jwt'))
  @ApiOkResponse({
    // type: StandardResponse<LoginResponseDto>,
    schema: {
      allOf: [
        { $ref: getSchemaPath(StandardResponse<PayStackBank[]>) },
        {
          properties: {
            payload: {
              // $ref: getSchemaPath(PayStackBank[]),
            },
          },
        },
      ],
    },
  })
  // @UseInterceptors(MapInterceptor(UserEntity, UserView))
  @HttpCode(HttpStatus.OK)
  async getBanks() {
    return this.utilitiesService.getBanks();
  }
}
