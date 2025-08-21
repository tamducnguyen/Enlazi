import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
  Length,
} from 'class-validator';
export class VerifyForgotPasswordDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  verify_code: string;
  @IsStrongPassword()
  @IsNotEmpty()
  password: string;
}
