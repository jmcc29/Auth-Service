// auth-service/src/auth/dtos/login-exchange.dto.ts
import { IsOptional, IsString } from 'class-validator';

export class LoginExchangeDto {
  @IsString()
  code!: string;

  @IsString()
  state!: string;

  @IsOptional()
  @IsString()
  sid?: string;
}

export interface LoginExchangeRes {
  sid: string;
  returnTo: string;
}
