import { IsEmail, IsString, Length } from 'class-validator';
export class VerifyDTO {
  @IsEmail()
  email: string;
  @IsString()
  @Length(6, 6)
  verify_code: string;
}
