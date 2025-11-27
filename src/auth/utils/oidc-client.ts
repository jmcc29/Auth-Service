// src/config/oidc-clients.ts
import { OidcClientsDict, OidcClientCfg } from '../../config/envs';

const clientsMap: Map<string, OidcClientCfg> = new Map(Object.entries(OidcClientsDict));

export const getClient = (clientId: string) => clientsMap.get(clientId);
export const getSecret = (clientId: string) => clientsMap.get(clientId)?.secret;
export const getOrigins = (clientId: string) => clientsMap.get(clientId)?.origins ?? [];
export const isOriginAllowed = (clientId: string, origin: string) => getOrigins(clientId).includes(origin);

export const allOrigins = (): string[] => {
  const set = new Set<string>();
  for (const cfg of clientsMap.values()) (cfg.origins ?? []).forEach(o => set.add(o));
  return Array.from(set);
};

// opcional: constantes convenientes
export const HubClientId = 'hub-interface';
export const BeneficiaryClientId = 'beneficiary-interface';
