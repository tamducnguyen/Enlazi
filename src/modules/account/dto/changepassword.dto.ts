import { IsNotEmpty, IsString, IsStrongPassword } from 'class-validator';

export class ChangePasswordDTO {
  @IsString()
  @IsNotEmpty()
  oldPassword: string;
  @IsString()
  @IsStrongPassword()
  newPassword: string;
  @IsString()
  confirmNewPassword: string;
}
