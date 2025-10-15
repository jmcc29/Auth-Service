import { Inject, Injectable } from '@nestjs/common';
import { KeycloakEnvs, FrontEnvs } from '../config/envs';
import { PENDING_STORE, SESSION_STORE } from '../session/session.module';
import { PendingStore } from '../session/pending/pending.store';
import { SessionStore } from '../session/store/session.store';
import { SessionData } from '../session/session.types';
import {
  authorizeEndpoint,
  tokenRequest,
  logoutRequest,
} from '../keycloak/kc-oidc.client';
import { KcJwksService } from '../keycloak/kc-jwks.service';
import { generatePkce } from './utils/pkce.util';
import { originOf } from './utils/origins.util';
import { randomId } from './utils/crypto.util';
import { peekRoles, peekSub } from './utils/jwt.util';

type ClientCfg = { id?: string; secret?: string };
const ALLOWED_CLIENTS: Readonly<Record<string, { secret?: string }>> = (() => {
  const map: Record<string, { secret?: string }> = {};
  for (const c of KeycloakEnvs.clientList ?? [])
    map[c.id] = { secret: c.secret };
  const hub = KeycloakEnvs.client?.hubInterface as ClientCfg | undefined;
  const ben = KeycloakEnvs.client?.beneficiaryInterface as
    | ClientCfg
    | undefined;
  if (hub?.id) map[hub.id] = { secret: hub.secret };
  if (ben?.id) map[ben.id] = { secret: ben.secret };
  return Object.freeze(map);
})();

function ensureClientAllowed(clientId: string) {
  if (!clientId || !ALLOWED_CLIENTS[clientId])
    throw new Error(`client_id no permitido: ${clientId}`);
}

@Injectable()
export class AuthService {
  constructor(
    @Inject(PENDING_STORE) private readonly pending: PendingStore,
    @Inject(SESSION_STORE) private readonly sessions: SessionStore,
    private readonly jwks: KcJwksService,
  ) {}

  private deriveRedirectUri(returnTo: string, clientId: string) {
    const origin = originOf(returnTo);
    // Validación simple: que esté en la whitelist global; si quieres por cliente, añade util más estricta.
    if (!FrontEnvs.frontendServers.includes(origin))
      throw new Error('Origen no permitido');
    return `${origin}/api/auth/callback`;
  }

  async buildAuthUrl({
    returnTo,
    clientId,
  }: {
    returnTo: string;
    clientId: string;
  }) {
    ensureClientAllowed(clientId);
    const { verifier, challenge } = generatePkce();
    const state = randomId();
    const redirectUri = this.deriveRedirectUri(returnTo, clientId);

    await this.pending.set(state, {
      codeVerifier: verifier,
      clientId,
      redirectUri,
      returnTo,
      createdAt: Date.now(),
    });

    const url = new URL(authorizeEndpoint());
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid profile email');
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return { url: url.toString(), state };
  }

  async exchangeCode({
    code,
    state,
    sid,
  }: {
    code: string;
    state: string;
    sid?: string;
  }) {
    const stash = await this.pending.take(state);
    if (!stash) throw new Error('State no encontrado o expirado');

    const { clientId, codeVerifier, redirectUri, returnTo } = stash;
    ensureClientAllowed(clientId);
    const secret = ALLOWED_CLIENTS[clientId]?.secret;

    const data = await tokenRequest({
      grant_type: 'authorization_code',
      client_id: clientId,
      ...(secret ? { client_secret: secret } : {}),
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
    });

    const now = Date.now();
    const expiresAt = now + (data.expires_in ?? 300) * 1000;
    const sub = peekSub(data.access_token);
    const roles = peekRoles(data.access_token, clientId);

    const sessionId = sid ?? randomId();
    const existing =
      (await this.sessions.get(sessionId)) ??
      ({
        tokenType: data.token_type ?? 'Bearer',
        sub,
        clients: {},
      } as SessionData);

    existing.tokenType = data.token_type ?? existing.tokenType ?? 'Bearer';
    existing.sub = existing.sub ?? sub;
    existing.clients[clientId] = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      idToken: data.id_token,
      expiresAt,
      roles,
    };

    await this.sessions.set(sessionId, existing);
    await this.sessions.gc();

    return { sid: sessionId, returnTo };
  }

  async getSessionData(sid: string, clientId: string) {
    const s = await this.sessions.get(sid);
    if (!s) throw new Error('Sesión inválida o expirada');
    const set = s.clients?.[clientId];
    if (!set) throw new Error('No hay tokens para el client_id solicitado');

    return {
      tokenType: s.tokenType,
      sub: s.sub,
      clientId,
      accessToken: set.accessToken, // si no quieres exponerlo, elimínalo aquí o en el gateway
      expiresAt: set.expiresAt,
      roles: set.roles,
    };
  }

  async verifySessionAccessToken(sid: string, clientId: string) {
    const s = await this.sessions.get(sid);
    if (!s) return { isValid: false };
    const set = s.clients?.[clientId];
    if (!set?.accessToken) return { isValid: false };
    const allowed = Object.keys(ALLOWED_CLIENTS);
    return this.jwks.verifyAccessToken(set.accessToken, allowed);
  }

  async getProfile(sid: string, clientId: string) {
    const s = await this.sessions.get(sid);
    if (!s) throw new Error('Sesión inválida o expirada');
    const set = s.clients?.[clientId];
    if (!set?.accessToken) throw new Error('No hay access_token');
    const sub = peekSub(set.accessToken);
    return { sub };
  }

  async logout(sid: string) {
    const s = await this.sessions.get(sid);
    if (!s) return;
    try {
      for (const [clientId, set] of Object.entries(s.clients ?? {})) {
        if (set.refreshToken) {
          const secret = ALLOWED_CLIENTS[clientId]?.secret;
          await logoutRequest(set.refreshToken, { id: clientId, secret });
        }
      }
    } finally {
      await this.sessions.del(sid);
    }
  }
}
