import axios from 'axios';
import { KeycloakEnvs } from '../config/envs';

function tokenEndpoint() {
  return `${KeycloakEnvs.authServerUrl}/realms/${encodeURIComponent(KeycloakEnvs.realm)}/protocol/openid-connect/token`;
}
function logoutEndpoint() {
  return `${KeycloakEnvs.authServerUrl}/realms/${encodeURIComponent(KeycloakEnvs.realm)}/protocol/openid-connect/logout`;
}
export function authorizeEndpoint() {
  return `${KeycloakEnvs.authServerUrl}/realms/${encodeURIComponent(KeycloakEnvs.realm)}/protocol/openid-connect/auth`;
}

export async function tokenRequest(body: Record<string, string>) {
  const { data } = await axios.post(tokenEndpoint(), new URLSearchParams(body), {
    headers: { 'content-type': 'application/x-www-form-urlencoded' }, timeout: 10000,
  });
  return data;
}

export async function logoutRequest(refreshToken: string, client: { id: string; secret?: string }) {
  const body = new URLSearchParams();
  body.set('client_id', client.id);
  if (client.secret) body.set('client_secret', client.secret);
  body.set('refresh_token', refreshToken);
  await axios.post(logoutEndpoint(), body, {
    headers: { 'content-type': 'application/x-www-form-urlencoded' }, timeout: 8000,
  });
}
