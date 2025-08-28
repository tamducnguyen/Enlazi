import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class RefreshDTO {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
  @IsUUID()
  @IsNotEmpty()
  sessionId: string;
}
