import { IsNotEmpty, IsString, IsUUID, IsOptional } from 'class-validator';

export class SignOutDTO {
  @IsString()
  @IsOptional()
  @IsNotEmpty()
  refreshToken: string;
  @IsOptional()
  @IsUUID()
  sessionId: string;
}
