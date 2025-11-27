import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { PENDING_STORE, SESSION_STORE } from '../session/session.module';
import { PendingStore } from '../session/pending/pending.store';
import { SessionStore } from '../session/store/session.store';
import {
  ensureClientAllowed,
  resolveClientIdOrThrow,
} from './utils/helpers/clients';
import {
  ensureOriginAllowedForReturnTo,
  deriveRedirectUriFromReturnTo,
} from './utils/helpers/clients';
import { generatePkce } from './utils/helpers/pkce';
import { randomId } from './utils/helpers/crypto';
import {
  ExchangeCodeDto,
  ExchangeCodeResDto,
  LoginStartDto,
  LogoutDto,
  LoginStartResDto,
  GetProfileDto,
  GetProfileRes,
  VerifyTokenDto,
  VerifyTokenRes,
  GetPermissionsDto,
  GetPermissionsRes,
  EvaluatePermissionDto,
  EvaluatePermissionRes,
} from './dtos';
import { KeycloakService } from 'src/keycloak/keycloak.service';
import { getSecret } from './utils/oidc-client';
import { peekRoles, peekSub, peekUserProfile } from './utils/helpers/jwt-peek';
import { SessionData } from 'src/session/session.types';

const PENDING_TTL_MS = 10 * 60 * 1000; // 10 minutos para state+verifier

@Injectable()
export class AuthService {
  constructor(
    private readonly keycloak: KeycloakService,
    @Inject(PENDING_STORE) private readonly pending: PendingStore,
    @Inject(SESSION_STORE) private readonly sessions: SessionStore,
  ) {}

  async loginStartHandler({
    clientId,
    returnTo,
  }: LoginStartDto): Promise<LoginStartResDto> {
    // 1) Validaciones
    ensureClientAllowed(clientId);
    ensureOriginAllowedForReturnTo(clientId, returnTo);

    // 2) Derivar redirectUri
    const redirectUri = deriveRedirectUriFromReturnTo(returnTo);

    // 3) Generar PKCE + state
    const { verifier, challenge, method } = generatePkce();
    const state = randomId(32); // 256 bits

    // 4) Guardar stash en PendingStore
    await this.pending.set(
      state,
      {
        codeVerifier: verifier,
        clientId: clientId,
        redirectUri,
        returnTo: returnTo,
        createdAt: Date.now(),
      },
      PENDING_TTL_MS,
    );

    // 5) Construir authUrl
    const authUrl = this.keycloak.authorizeUrl({
      clientId: clientId,
      redirectUri,
      state,
      pkce: { challenge, method },
    });
    // 6) Responder
    return { ok: true, url: authUrl, state };
  }

  async exchangeCode({
    code,
    state,
    sid,
  }: ExchangeCodeDto): Promise<ExchangeCodeResDto> {
    const stash = await this.pending.take(state);
    if (!stash) throw new BadRequestException('State no encontrado o expirado');

    const { clientId, codeVerifier, redirectUri, returnTo } = stash;
    ensureClientAllowed(clientId);

    const clientSecret = getSecret(clientId);

    const data = await this.keycloak.tokenRequest(
      clientId,
      clientSecret,
      code,
      codeVerifier,
      redirectUri,
    );

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
    console.log('Token:', data.access_token);

    await this.sessions.set(sessionId, existing);
    await this.sessions.gc();

    return { ok: true, sid: sessionId, returnTo };
  }

  async logout({ sid }: LogoutDto) {
    const session = await this.sessions.get(sid);
    if (!session) return; // idempotente

    const entries = Object.entries(session.clients ?? {});

    for (const [clientId, clientSet] of entries) {
      const refresh = clientSet.refreshToken;
      if (!refresh) continue;
      try {
        const secret = getSecret(clientId);
        await this.keycloak.logoutRequest(refresh, { id: clientId, secret });
      } catch (e) {
        console.warn(`Logout failed for ${clientId}:`, e.message);
      }
    }
    await this.sessions.del(sid);
  }

  async getProfileByCtx(dto: GetProfileDto): Promise<GetProfileRes> {
    // 1) Sesión
    const session = await this.sessions.get(dto.sid);
    if (!session) throw new BadRequestException('Sesión inválida o expirada');

    // 2) Resolver clientId (clientId > origin > referer)
    const { clientId } = resolveClientIdOrThrow({
      clientId: dto.clientId,
      origin: dto.origin,
    });

    // 3) Tomar access_token del cliente
    const set = session.clients?.[clientId];
    if (!set?.accessToken) {
      throw new BadRequestException(
        `No hay access_token para el client_id solicitado (${clientId})`,
      );
    }

    // 4) Armar perfil desde el access_token
    const profile = peekUserProfile(set.accessToken);
    const roles = set.roles ?? peekRoles(set.accessToken, clientId) ?? [];
    const sub = session.sub ?? profile?.sub ?? peekSub(set.accessToken);

    return {
      ok: true,
      clientId,
      sub: sub || '',
      username: profile?.username ?? profile?.preferred_username,
      name: profile?.name,
      givenName: profile?.given_name,
      familyName: profile?.family_name,
      email: profile?.email,
      roles,
    };
  }

  async verifyToken(dto: VerifyTokenDto): Promise<VerifyTokenRes> {
    // 1) Sesión
    const session = await this.sessions.get(dto.sid);
    if (!session) throw new BadRequestException('Sesión inválida o expirada');

    // 2) Resolver clientId (clientId > origin > referer)
    const { clientId } = resolveClientIdOrThrow({
      clientId: dto.clientId,
      origin: dto.origin,
    });

    // 3) Tomar access_token del cliente
    const set = session.clients?.[clientId];
    if (!set?.accessToken) {
      throw new BadRequestException(
        `No hay access_token para el client_id/origin solicitado (${clientId})`,
      );
    }
    // 4) Verificación criptográfica (firma/issuer/tiempos y opcionalmente azp)
    try {
      const checkAzp = dto.checkAzp ?? true;
      const clockSkew = dto.clockSkewSec ?? 90;

      await this.keycloak.verifyAccessToken(set.accessToken, {
        azp: checkAzp ? clientId : undefined,
        clockSkewSec: clockSkew,
      });

      // Si no lanza, el token es válido ahora mismo
      return { ok: true, exists: true, isValid: true };
    } catch (e) {
      console.warn('Token verification failed:', e.message);
      // Firma expirada, issuer incorrecto, azp mismatch, etc.
      return { ok: true, exists: true, isValid: false };
    }
  }

  async getPermissions(dto: GetPermissionsDto): Promise<GetPermissionsRes> {
    // 1) Sesión
    const session = await this.sessions.get(dto.sid);
    if (!session) throw new BadRequestException('Sesión inválida o expirada');

    // 2) Resolver clientId (clientId > origin > referer)
    const { clientId } = resolveClientIdOrThrow({
      clientId: dto.clientId,
      origin: dto.origin,
    });

    // 3) Tomar access_token del cliente
    const set = session.clients?.[clientId];
    if (!set?.accessToken) {
      throw new BadRequestException(
        `No hay access_token para el client_id solicitado (${clientId})`,
      );
    }

    // 4) Hacer UMA request para listar permisos
    const data = await this.keycloak.umaRequest({
      accessToken: set.accessToken,
      audience: dto.audience,
      responseMode: 'permissions',
    });

    return {
      ok: true,
      audience: dto.audience,
      permissions: data,
    };
  }

  async evaluatePermission(
    dto: EvaluatePermissionDto,
  ): Promise<EvaluatePermissionRes> {
    const { sid, origin, audience, resource, scope } = dto;
    console.log('Evaluating permission request:', dto);

    // 1) Sesión
    const session = await this.sessions.get(dto.sid);
    if (!session) throw new BadRequestException('Sesión inválida o expirada');

    // 2) Resolver clientId (clientId > origin > referer)
    const { clientId } = resolveClientIdOrThrow({
      clientId: dto.clientId,
      origin: dto.origin,
    });

    // 3) Tomar access_token del cliente
    const set = session.clients?.[clientId];
    if (!set?.accessToken) {
      throw new BadRequestException(
        `No hay access_token para el client_id solicitado (${clientId})`,
      );
    }

    // 4) Llamar UMA en modo "decision"
    let raw: any;
    let granted = false;

    try {
      raw = await this.keycloak.umaRequest({
        accessToken: set.accessToken,
        audience,
        responseMode: 'decision',
        permission: `${resource}#${scope}`,
      });

      console.log('UMA raw response:', raw);
      // Keycloak suele devolver { result: true|false }
      granted = !!raw?.result;
    } catch (err: any) {
      // Aquí depende de cómo venga el error de tu cliente HTTP
      // Ejemplo típico con axios: err.response.status === 403
      const status = err?.response?.status ?? err?.status;

      if (status === 403 || status === 401) {
        console.log('UMA denied permission (expected):', {
          status,
          sid,
          clientId,
          audience,
          resource,
          scope,
        });
        granted = false;
      } else {
        console.error('UMA unexpected error:', err);
        throw err;
      }
    }


    return {
      ok: true,
      audience,
      resource,
      scope,
      granted,
    };
  }
}
