import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class SignOutDTO {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
  @IsUUID()
  @IsNotEmpty()
  sessionId: string;
}
