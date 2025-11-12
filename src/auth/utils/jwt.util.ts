export type Decoded = any;

export function decodeJwt<T = Decoded>(jwt?: string): T | undefined {
  try {
    if (!jwt) return;
    const [, p] = jwt.split('.');
    return JSON.parse(Buffer.from(p, 'base64').toString('utf8')) as T;
  } catch {
    return;
  }
}

export function peekSub(jwt?: string) {
  const j = decodeJwt<any>(jwt);
  return j?.sub as string | undefined;
}
export function peekRoles(jwt?: string, clientId?: string) {
  const j = decodeJwt<any>(jwt);
  const realm: string[] = j?.realm_access?.roles ?? [];
  const client: string[] = clientId
    ? (j?.resource_access?.[clientId]?.roles ?? [])
    : [];
  return Array.from(new Set([...realm, ...client]));
}

export function peekUserProfile(jwt?: string) {
  try {
    if (!jwt) return;
    const [, p] = jwt.split('.');
    const j = JSON.parse(Buffer.from(p, 'base64').toString('utf8'));
    return {
      sub: j?.sub as string | undefined,
      username: j?.preferred_username as string | undefined,
      name: j?.name as string | undefined,
      given_name: j?.given_name as string | undefined,
      family_name: j?.family_name as string | undefined,
      email: j?.email as string | undefined,
    };
  } catch {
    return;
  }
}
