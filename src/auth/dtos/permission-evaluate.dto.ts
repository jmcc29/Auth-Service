import { IsOptional, IsString } from 'class-validator';

export class PermissionEvaluateDto {
  @IsString()
  sid!: string;

  @IsString()
  audience!: string; // resource-server clientId (API)

  @IsString()
  resource!: string; // rsname en Keycloak (UMA)

  @IsString()
  scope!: string;    // scope UMA

  @IsOptional()
  @IsString()
  clientId?: string;

  @IsOptional()
  @IsString()
  origin?: string;

  @IsOptional()
  @IsString()
  referer?: string;
}

export type PermissionEvaluateRes = {
  ok: true;
  audience: string;
  resource: string;
  scope: string;
  allowed: boolean;
};
