import { IsOptional, IsString } from 'class-validator';

export class PermissionsListDto {
  @IsString()
  sid!: string;

  @IsString()
  audience!: string; // resource-server clientId (API)

  @IsOptional()
  @IsString()
  clientId?: string; // opcional override, se valida contra origin

  @IsOptional()
  @IsString()
  origin?: string;   // preferido para resolver clientId

  @IsOptional()
  @IsString()
  referer?: string;  // fallback si no hay origin
}

export type PermissionsListRes = {
  ok: true;
  audience: string;
  permissions: string[]; // normalizados "recurso:scope"
};
