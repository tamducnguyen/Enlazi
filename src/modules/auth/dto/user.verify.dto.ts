import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';
export class VerifyDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  verify_code: string;
}
