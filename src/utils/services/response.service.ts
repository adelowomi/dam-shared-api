import { HttpStatus, Injectable } from '@nestjs/common';

@Injectable()
export class ResponseService {
  Response(
    success: boolean,
    message: string,
    status:HttpStatus,
    payload: Record<string, unknown>,
  ) {
    return { success, message, payload,status };
  }
}
