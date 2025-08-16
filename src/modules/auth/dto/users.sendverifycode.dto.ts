import { IsEmail } from 'class-validator';

export class SendVerifyCodeDTO {
  @IsEmail()
  email: string;
}
