import { IsEmail, IsString, IsStrongPassword, Length } from 'class-validator';
export class VerifyForgotPasswordDTO {
  @IsEmail()
  email: string;
  @IsString()
  @Length(6, 6)
  verify_code: string;
  @IsStrongPassword()
  password: string;
}
