import { IsNotEmpty, IsString } from 'class-validator';

export class EvaluatePermissionDto {
  @IsString()
  @IsNotEmpty()
  accessToken: string;
  @IsString()
  @IsNotEmpty()
  resource: string;
  @IsString()
  @IsNotEmpty()
  scope: string;
}
