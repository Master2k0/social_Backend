import { ArgumentsHost, Catch, ExceptionFilter } from '@nestjs/common';
import { Response } from 'express';
import { MongoServerError } from 'mongodb';

@Catch(MongoServerError)
export class MongooseExceptionFilter implements ExceptionFilter {
  catch(exception: MongoServerError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    // const message = exception.message;
    const statusCode = exception.code;
    // console.log(response);
    // console.log(message);
    console.log(exception);
    switch (statusCode) {
      case 11000:
        response.status(409).json({
          statusCode: 409,
          message: `${Object.keys(exception.keyValue)} already exists`,
        });
        break;
      case 64:
        response.status(500).json({
          statusCode: 500,
          message: "sever can't write database",
        });
        break;
      case 17:
        response.status(501).json({
          statusCode: 501,
          message: 'sever can not connect to database',
        });
        break;
      case 112:
        response.status(409).json({
          statusCode: 409,
          message: 'Write conflict',
        });
        break;
      case 11600:
        response.status(503).json({
          statusCode: 503,
          message: 'Can not connect to database',
        });
        break;
      case 211:
        response.status(503).json({
          statusCode: 503,
          message: 'Can not connect to database',
        });
        break;
      default:
        response.status(500).json({
          statusCode: 500,
          message: 'Internal server error',
        });
    }
  }
}
