import { ArgumentsHost, Catch, ExceptionFilter } from '@nestjs/common';
import { AbstractHttpAdapter } from '@nestjs/core';
import {
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError,
} from 'jsonwebtoken';

@Catch(TokenExpiredError, JsonWebTokenError, NotBeforeError)
export class JwtExceptionFilter implements ExceptionFilter {
  constructor(private readonly httpAdapter: AbstractHttpAdapter) {}
  catch(exception: unknown, host: ArgumentsHost) {
    console.log(exception);
    const ctx = host.switchToHttp();
    if (exception) {
      const responseBody = {
        statusCode: 401,
        message: (exception as JsonWebTokenError).message,
      };
      this.httpAdapter.reply(ctx.getResponse(), responseBody, 401);
    }
  }
}
