import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
  Length,
} from 'class-validator';
export class SignUpDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;
  @IsString()
  @IsNotEmpty()
  @Length(5, 32)
  username: string;
  @IsStrongPassword()
  @IsNotEmpty()
  password: string;
}
