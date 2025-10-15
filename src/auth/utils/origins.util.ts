import { KeycloakEnvs, FrontEnvs } from '../../config/envs';
export function originOf(urlStr: string): string {
  const { origin } = new URL(urlStr);
  return origin.replace(/\/+$/, '');
}
export function allowedOriginsForClient(clientId: string): string[] {
  const perClient = (KeycloakEnvs.clientList ?? []).find(c => c.id === clientId)?.origins ?? [];
  const global = FrontEnvs.frontendServers ?? [];
  return Array.from(new Set([...perClient, ...global]));
}
export function assertAllowedOrigin(origin: string, clientId: string) {
  const allowed = allowedOriginsForClient(clientId);
  if (!allowed.includes(origin)) {
    throw new Error(`Origen no permitido para ${clientId}: ${origin}`);
  }
}
