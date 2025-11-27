import 'dotenv/config';
import joi from 'joi';

/* ================== Tipos básicos ================== */
export type OidcClientCfg = { secret?: string; origins?: string[] };
export type OidcClientsRecord = Record<string, OidcClientCfg>;

/* ================== Helpers internos ================== */
const uniq = <T,>(arr: T[] = []) => Array.from(new Set(arr));
const safeJson = <T,>(raw: string | undefined, fallback: T): T => {
  if (!raw) return fallback;
  try { return JSON.parse(raw) as T; } catch { return fallback; }
};

/* ================== Esquemas JOI ================== */
const oidcClientSchema = joi.object({
  secret: joi.string().allow('', null),
  origins: joi.array().items(joi.string().uri()).default([]),
});

const oidcClientsRecordSchema = joi
  .object()
  .pattern(/^[\w.\-:]+$/, oidcClientSchema) // claves = client_id
  .min(1);

/* ============================================================
   INTERFAZ DE VARIABLES DE ENTORNO
============================================================ */
interface EnvVars {
  NATS_SERVERS: string[];
  DB_PASSWORD: string;
  DB_DATABASE: string;
  DB_HOST: string;
  DB_PORT: number;
  DB_USERNAME: string;
  DB_SYNCHRONIZE: boolean;
  DB_SCHEMA: string;
  LDAP_AUTHENTICATION: boolean;
  LDAP_HOST: string;
  LDAP_PORT: number;
  LDAP_ADMIN_PREFIX: string;
  LDAP_ADMIN_USERNAME: string;
  LDAP_ADMIN_PASSWORD: string;
  LDAP_ACCOUNT_PREFIX: string;
  LDAP_ACCOUNT_SUFFIX: string;
  LDAP_BASEDN: string;
  JWT_SECRET: string;
  API_KEY: string;
  PVTBE_USERNAME: string;
  PVTBE_PASSWORD: string;
  USER_TEST_DEVICE: string;
  USER_TEST_ACCESS: boolean;

  // ==== NUEVOS CAMPOS PARA KEYCLOAK ====
  KEYCLOAK_URL?: string;
  KEYCLOAK_REALM?: string;
  OIDC_CLIENTS?: string;
}

/* ============================================================
   VALIDACIÓN CON JOI
============================================================ */
const envsSchema = joi
  .object({
    NATS_SERVERS: joi.array().items(joi.string()).required(),

    LDAP_HOST: joi.string().required(),
    LDAP_PORT: joi.number().required(),
    LDAP_ADMIN_PREFIX: joi.string().required(),
    LDAP_ADMIN_USERNAME: joi.string().required(),
    LDAP_ADMIN_PASSWORD: joi.string().required(),
    LDAP_ACCOUNT_PREFIX: joi.string().required(),
    LDAP_ACCOUNT_SUFFIX: joi.string().required(),
    LDAP_BASEDN: joi.string().required(),

    JWT_SECRET: joi.string().required(),
    API_KEY: joi.string(),
    USER_TEST_DEVICE: joi.string(),
    USER_TEST_ACCESS: joi.boolean().default(false),

    DB_PASSWORD: joi.string().required(),
    DB_DATABASE: joi.string().required(),
    DB_HOST: joi.string().required(),
    DB_PORT: joi.number().required(),
    DB_USERNAME: joi.string().required(),
    DB_SYNCHRONIZE: joi.string().valid('true', 'false').default('false'),
    DB_SCHEMA: joi.string().default('beneficiaries'),

    // === NUEVOS CAMPOS ===
    KEYCLOAK_URL: joi.string().uri().required(),
    KEYCLOAK_REALM: joi.string().required(),
    OIDC_CLIENTS: joi.string().required(),
  })
  .unknown(true);

const { error, value } = envsSchema.validate({
  ...process.env,
  NATS_SERVERS: process.env.NATS_SERVERS?.split(','),
  DB_SYNCHRONIZE: process.env.DB_SYNCHRONIZE?.toLowerCase(),
});

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

const envVars: EnvVars = {
  ...value,
  DB_SYNCHRONIZE: value.DB_SYNCHRONIZE === 'true',
};


/* ============ Parseo y normalización OIDC_CLIENTS ============ */
const rawClients = safeJson<OidcClientsRecord>(value.OIDC_CLIENTS, {});
const { error: clientsErr, value: validatedClients } = oidcClientsRecordSchema.validate(rawClients, { abortEarly: false });
if (clientsErr) throw new Error(`OIDC_CLIENTS inválido: ${clientsErr.message}`);

// normaliza origins (únicos)
for (const cid of Object.keys(validatedClients)) {
  const cfg = validatedClients[cid];
  cfg.origins = uniq(cfg.origins ?? []);
}

/* ============================================================
   EXPORTS EXISTENTES (NO MODIFICADOS)
============================================================ */
export const NastEnvs = {
  natsServers: envVars.NATS_SERVERS,
};

export const LdapEnvs = {
  ldapAuthentication: envVars.LDAP_AUTHENTICATION,
  ldapHost: envVars.LDAP_HOST,
  ldapPort: envVars.LDAP_PORT,
  ldapAdminPrefix: envVars.LDAP_ADMIN_PREFIX,
  ldapAdminUsername: envVars.LDAP_ADMIN_USERNAME,
  ldapAdminPassword: envVars.LDAP_ADMIN_PASSWORD,
  ldapAccountPrefix: envVars.LDAP_ACCOUNT_PREFIX,
  ldapAccountSuffix: envVars.LDAP_ACCOUNT_SUFFIX,
  ldapBaseDN: envVars.LDAP_BASEDN,
};

export const SecretEnvs = {
  jwtSecret: envVars.JWT_SECRET,
  apiKey: envVars.API_KEY,
};

export const DbEnvs = {
  dbPassword: envVars.DB_PASSWORD,
  dbDatabase: envVars.DB_DATABASE,
  dbHost: envVars.DB_HOST,
  dbPort: envVars.DB_PORT,
  dbUsername: envVars.DB_USERNAME,
  dbSynchronize: envVars.DB_SYNCHRONIZE,
  dbSchema: envVars.DB_SCHEMA,
};

export const TestDeviceEnvs = {
  userTestDevice: envVars.USER_TEST_DEVICE,
  userTestAccess: envVars.USER_TEST_ACCESS,
};

/* ============================================================
   NUEVAS EXPORTS PARA KEYCLOAK Y FRONTENDS
============================================================ */
export const KeycloakEnvs = {
  authServerUrl: envVars.KEYCLOAK_URL!,
  realm: envVars.KEYCLOAK_REALM!,
};

/** Diccionario ya validado y normalizado de clientes OIDC */
export const OidcClientsDict: OidcClientsRecord = validatedClients;