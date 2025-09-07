import { IsNotEmpty, IsString, Length } from 'class-validator';

export class UpdateUserNameDTO {
  @IsString()
  @IsNotEmpty()
  @Length(4, 32)
  username: string;
}
