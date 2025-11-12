import { SessionData } from 'src/session/session.types';
import { KeycloakEnvs } from '../../config/envs';

export type ClientResolveInput = {
  clientId?: string;
  origin?: string;
  referer?: string;
};

export type ClientResolveResult = {
  clientId: string;
  matchedBy: 'clientId' | 'origin' | 'referer' | 'returnTo';
};

function normalizeOrigin(x?: string): string | undefined {
  if (!x) return;
  try {
    const { origin } = new URL(x);
    return origin;
  } catch {
    return;
  }
}

function findClientByOrigin(o?: string) {
  if (!o) return;
  const list = KeycloakEnvs.clientList ?? [];
  return list.find((c) => Array.isArray(c.origins) && c.origins.includes(o));
}

/**
 * Resuelve el clientId (y valida si hubo override).
 * Regla:
 *  - Si viene clientId: valida que el origin/referer (si vienen) pertenezcan a ese client.
 *  - Si NO viene clientId: intenta resolver por origin -> referer.
 *  - Si no hay match: throw.
 */
export function resolveClientIdOrThrow(
  input: ClientResolveInput,
): ClientResolveResult {
  const origin = normalizeOrigin(input.origin);
  const referer = normalizeOrigin(input.referer);

  // 1) Si viene clientId, validarlo si hay origin/referer
  if (input.clientId) {
    const list = KeycloakEnvs.clientList ?? [];
    const cfg = list.find((c) => c.id === input.clientId);
    if (!cfg) throw new Error(`client_id no permitido: ${input.clientId}`);

    // Si hay origin/referer, deben pertenecer a este cliente
    if (origin && !cfg.origins?.includes(origin)) {
      throw new Error(`origin no coincide con client_id solicitado`);
    }
    if (referer && !cfg.origins?.includes(referer)) {
      throw new Error(`referer no coincide con client_id solicitado`);
    }
    return { clientId: cfg.id, matchedBy: 'clientId' };
  }

  // 2) Resolver por origin
  const byOrigin = findClientByOrigin(origin);
  if (byOrigin) return { clientId: byOrigin.id, matchedBy: 'origin' };

  // 3) Resolver por referer
  const byRef = findClientByOrigin(referer);
  if (byRef) return { clientId: byRef.id, matchedBy: 'referer' };

  throw new Error('No se pudo resolver client_id por origin/referer');
}

/** Obtiene access_token del cliente FRONT (resuelto por origin) para firmar UMA */
export async function getAccessTokenForFrontendClient(
  sid: string,
  ctx: { clientId?: string; origin?: string; referer?: string },
) {
  const s = await this.sessions.get(sid);
  if (!s) throw new Error('Sesión inválida o expirada');

  const { clientId } = resolveClientIdOrThrow(ctx);
  const set = s.clients?.[clientId];
  if (!set?.accessToken)
    throw new Error('No hay access_token para el client_id resolvido');

  return { accessToken: set.accessToken, session: s as SessionData };
}
