import { IsNotEmpty, IsOptional, IsString, IsUUID } from 'class-validator';

export class RefreshDTO {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
  @IsOptional()
  @IsUUID()
  sessionId: string;
}
