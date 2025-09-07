import { Type } from 'class-transformer';
import {
  IsArray,
  IsNotEmpty,
  IsString,
  IsUUID,
  ValidateNested,
} from 'class-validator';
class HobbyDTO {
  @IsUUID()
  @IsNotEmpty()
  id: string;
  @IsString()
  @IsNotEmpty()
  name: string;
}
export class PostHobbiesDTO {
  @ValidateNested({ each: true })
  @Type(() => HobbyDTO)
  @IsArray()
  hobbies: HobbyDTO[];
}
