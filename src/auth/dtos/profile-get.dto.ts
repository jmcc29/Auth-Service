import { IsString } from 'class-validator';
export class ProfileGetDto {
  @IsString() sid!: string;
  @IsString() clientId!: string;
}
export type ProfileGetRes = {
  ok: true;
  sub?: string;
  username?: string;
  name?: string;
  email?: string;
};
