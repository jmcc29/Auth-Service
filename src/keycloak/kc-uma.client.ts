import axios from 'axios';
import { KeycloakEnvs } from '../config/envs';
import { UmaDecisionReq, UmaPermissionsReq } from './kc.types';

/**
 * Implementa las llamadas UMA a Keycloak usando el token endpoint con:
 * grant_type=urn:ietf:params:oauth:grant-type:uma-ticket
 *
 * response_mode:
 *  - "permissions": devuelve arreglo de permisos
 *  - "decision": devuelve { result: boolean }
 *
 * permission: `${resource}#${scope}` (para decision)
 */
const base = KeycloakEnvs.authServerUrl!;
const realm = KeycloakEnvs.realm!;

function tokenEndpoint() {
  return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`;
}

export async function umaRequest(
  req: UmaPermissionsReq | UmaDecisionReq,
): Promise<any> {
  const body = new URLSearchParams();
  body.set('grant_type', 'urn:ietf:params:oauth:grant-type:uma-ticket');
  body.set('audience', req.audience);
  body.set('response_mode', req.responseMode);

  if ('permission' in req && req.permission) {
    body.set('permission', req.permission);
  }

  const { data } = await axios.post(tokenEndpoint(), body, {
    headers: {
      authorization: `Bearer ${req.accessToken}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    timeout: 10_000,
  });

  return data;
}
