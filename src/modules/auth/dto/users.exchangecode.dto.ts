import { IsNotEmpty, IsString } from 'class-validator';

export class ExchangeCodeDTO {
  @IsString()
  @IsNotEmpty()
  code: string;
}
