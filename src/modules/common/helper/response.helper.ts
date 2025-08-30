import { HttpStatus } from '@nestjs/common';

export function sendResponse<T>(status: HttpStatus, message: string, data?: T) {
  const response = {
    status,
    message: message,
    data: data,
  };
  return response;
}
