/**
 * Keycloak UMA (response_mode=permissions) devuelve array de objetos que pueden tener:
 * - rsname (string)
 * - rsid (string)
 * - scopes (array<string>)
 *
 * Normalizamos a strings "resource:scope". Si no hay scopes => "resource:*"
 */
export function normalizeUmaPermissions(raw: any): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const p of raw) {
    const resource = p?.rsname ?? p?.rsid ?? 'unknown';
    const scopes: string[] = Array.isArray(p?.scopes) ? p.scopes : [];
    if (!scopes.length) {
      out.push(`${resource}:*`);
      continue;
    }
    for (const s of scopes) out.push(`${resource}:${s}`);
  }
  return Array.from(new Set(out));
}
