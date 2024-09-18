import { HttpStatus, Injectable } from '@nestjs/common';

@Injectable()
export class ResponseService {
  Response<T>(
    success: boolean,
    message: string,
    status: HttpStatus,
    payload?: T,
    errors?: any,
  ): StandardResponse<T> {
    return { success, message, payload, status, errors };
  }

  success<T>(message: string, payload?: T): StandardResponse<T> {
    return this.Response(true, message, HttpStatus.OK, payload);
  }

  error<T>(
    message: string,
    status: HttpStatus = HttpStatus.BAD_REQUEST,
    errors?: any,
  ): StandardResponse<T> {
    return this.Response(false, message, status, null as T, errors);
  }

  notFound<T>(message: string): StandardResponse<T> {
    return this.error(message, HttpStatus.NOT_FOUND);
  }

  unauthorized<T>(message: string): StandardResponse<T> {
    return this.error(message, HttpStatus.UNAUTHORIZED);
  }

  forbidden<T>(message: string): StandardResponse<T> {
    return this.error(message, HttpStatus.FORBIDDEN);
  }

  badRequest<T>(message: string): StandardResponse<T> {
    return this.error(message);
  }

  internalServerError<T>(message: string, error?: any): StandardResponse<T> {
    return this.error(message, HttpStatus.INTERNAL_SERVER_ERROR, error);
  }
}
export class StandardResponse<T> {
  constructor(
    public success: boolean,
    public message: string,
    public status: HttpStatus,
    public payload?: T,
    public errors?: any,
  ) {}
}

// export function withStandardResponse<TBase extends new (...args: any[]) => {}>(
//   Base: TBase,
// ) {
//   return class extends Base {
//     responseService = new ResponseService();
//   };
// }

// create a mixin to add the Standard Response to any class
