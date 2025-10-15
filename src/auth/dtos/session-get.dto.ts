import { IsString } from 'class-validator';

export class SessionGetDto {
  @IsString() sid!: string;
  @IsString() clientId!: string;
}
export type SessionGetRes = {
  ok: true;
  tokenType: string;
  sub?: string;
  clientId: string;
  accessToken?: string | undefined;
  expiresAt?: number;
  roles?: string[];
};
