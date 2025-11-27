// Helpers para validar el cliente y su whitelist de orígenes
import { BadRequestException } from '@nestjs/common';
import { getClient, isOriginAllowed, getOrigins } from '../../utils/oidc-client';
import { originOf } from './origins';

/** Lanza si el clientId no existe en OIDC_CLIENTS */
export function ensureClientAllowed(clientId: string) {
  const c = getClient(clientId);
  if (!clientId || !c) {
    throw new Error(`client_id no permitido: ${clientId}`);
  }
}

/** Lanza si el origin(returnTo) no está permitido para el clientId */
export function ensureOriginAllowedForReturnTo(clientId: string, returnTo: string) {
  const origin = originOf(returnTo);
  if (!isOriginAllowed(clientId, origin)) {
    const list = getOrigins(clientId).join(', ');
    throw new Error(`Origen no permitido para client_id ${clientId}. Recibido: ${origin}. Permitidos: [${list}]`);
  }
}

/** Deriva el redirectUri fijo para el frontend dado (callback estándar) */
export function deriveRedirectUriFromReturnTo(returnTo: string) {
  const origin = originOf(returnTo);
  return `${origin}/api/auth/callback`;
}

export function findClientIdByOrigin(origin: string): string | undefined {
  // Recorre el diccionario y retorna el primer clientId cuyo origins incluye el origin dado.
  // OJO: si hay varios clientes con el mismo origin, define una política (por ahora, el primero).
  // Puedes optimizar esto manteniendo un índice invertido en memoria.
  const dict = Object.entries(require('../../../config/envs').OidcClientsDict as Record<string, { origins?: string[] }>);
  for (const [cid, cfg] of dict) {
    if ((cfg.origins ?? []).includes(origin)) return cid;
  }
  return undefined;
}

/** Devuelve { clientId, origin? } o lanza si no puede resolver */
export function resolveClientIdOrThrow(ctx: { clientId?: string; origin?: string; referer?: string }) {
  // 1) Si viene clientId explícito y existe, úsalo.
  if (ctx.clientId) {
    const exists = !!getClient(ctx.clientId);
    if (!exists) throw new BadRequestException(`client_id no permitido: ${ctx.clientId}`);
    return { clientId: ctx.clientId, origin: ctx.origin };
  }

  // 2) Derivar origin desde origin o referer.
  const origin = ctx.origin
    || (ctx.referer ? originOf(ctx.referer) : undefined);

  if (!origin) throw new BadRequestException('No se pudo resolver el client_id (falta clientId/origin/referer)');

  // 3) Buscar clientId por origin.
  const cid = findClientIdByOrigin(origin);
  if (!cid) throw new BadRequestException(`No se encontró client_id para el origin: ${origin}`);

  // Validación suave: el origin debe estar registrado para ese cliente.
  const allowed = getOrigins(cid);
  if (!allowed.includes(origin)) {
    throw new BadRequestException(`Origen ${origin} no está permitido para client_id ${cid}`);
  }

  return { clientId: cid, origin };
}