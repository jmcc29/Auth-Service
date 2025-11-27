/** Decodifica un JWT (sin verificar) y devuelve payload como objeto. */
export function peekJwtPayload<T = any>(jwt: string): T {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Error('JWT mal formado');
  const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  return JSON.parse(json) as T;
}

/** Extrae sub del access token (sin verificar) */
export function peekSub(jwt: string): string | undefined {
  try { return (peekJwtPayload(jwt) as any)?.sub; } catch { return undefined; }
}

/**
 * Extrae roles del realm/client.
 * Para Keycloak, suelen estar en `realm_access.roles` y `resource_access[clientId].roles`
 */
export function peekRoles(jwt: string, clientId?: string): string[] {
  try {
    const p: any = peekJwtPayload(jwt);
    const realm = Array.isArray(p?.realm_access?.roles) ? p.realm_access.roles : [];
    const client = Array.isArray(p?.resource_access?.[clientId || '']?.roles)
      ? p.resource_access[clientId!].roles
      : [];
    return Array.from(new Set<string>([...realm, ...client]));
  } catch { return []; }
}

export function peekUserProfile(jwt: string): {
  sub?: string;
  preferred_username?: string;
  username?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
} | undefined {
  try {
    const p: any = peekJwtPayload(jwt);
    return {
      sub: p?.sub,
      preferred_username: p?.preferred_username,
      username: p?.preferred_username ?? p?.username,
      name: p?.name,
      given_name: p?.given_name,
      family_name: p?.family_name,
      email: p?.email,
    };
  } catch {
    return undefined;
  }
}
