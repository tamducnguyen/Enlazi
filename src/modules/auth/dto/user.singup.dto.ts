import { IsEmail, IsString, IsStrongPassword, Length } from 'class-validator';
export class SignUpDTO {
  @IsEmail()
  email: string;
  @IsString()
  @Length(5, 32)
  username: string;
  @IsStrongPassword()
  password: string;
}
