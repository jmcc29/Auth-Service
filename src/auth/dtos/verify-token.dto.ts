import { IsString } from 'class-validator';

export class VerifyTokenDto {
  @IsString() sid!: string;
  @IsString() clientId!: string;
}
export type VerifyTokenRes = { ok: true; isValid: boolean; sub?: string; exp?: number; azp?: string };
