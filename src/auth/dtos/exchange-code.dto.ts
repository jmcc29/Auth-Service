// auth-service/src/auth/dtos/login-exchange.dto.ts
import { IsOptional, IsString } from 'class-validator';

export class ExchangeCodeDto {
  @IsString()
  code!: string;

  @IsString()
  state!: string;

  @IsOptional()
  @IsString()
  sid?: string;
}

export interface ExchangeCodeResDto {
  ok:true;
  sid: string;
  returnTo: string;
}
