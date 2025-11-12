import { IsOptional, IsString } from 'class-validator';
export class ProfileGetDto {
  @IsString() sid!: string;

  @IsOptional()
  @IsString()
  clientId?: string;

  @IsOptional()
  @IsString()
  origin?: string;

  @IsOptional()
  @IsString()
  referer?: string;

  @IsOptional()
  @IsString()
  audience?: string;
}
export type ProfileGetRes = {
  ok: true;
  clientId: string;
  sub?: string;
  username: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  email?: string;
  roles?: string[];
};
