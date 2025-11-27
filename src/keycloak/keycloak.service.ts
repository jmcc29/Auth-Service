// keycloak.service.ts
import { Injectable } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import * as jose from 'jose-node-cjs-runtime';
import { KeycloakEnvs } from '../config/envs';

@Injectable()
export class KeycloakService {
  private readonly base: string;
  private readonly realm: string;
  private readonly http: AxiosInstance;
  private readonly jwks: ReturnType<typeof jose.createRemoteJWKSet>;

  constructor() {
    this.base = KeycloakEnvs.authServerUrl || 'http://localhost:8080';
    this.realm = KeycloakEnvs.realm || 'muserpol';
    this.http = axios.create({
      baseURL: this.issuer(),
      timeout: 10000,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });

    // JWKS cacheado (singleton en la instancia del service)
    this.jwks = jose.createRemoteJWKSet(new URL(this.certsEndpoint()));
  }

  // --- Helpers de URLs
  private issuer() {
    return `${this.base}/realms/${encodeURIComponent(this.realm)}`;
  }
  private tokenEndpoint() {
    return `${this.issuer()}/protocol/openid-connect/token`;
  }
  private logoutEndpoint() {
    return `${this.issuer()}/protocol/openid-connect/logout`;
  }
  private authorizeEndpoint() {
    return `${this.issuer()}/protocol/openid-connect/auth`;
  }
  private certsEndpoint() {
    return `${this.issuer()}/protocol/openid-connect/certs`;
  }

  // --- Flujos OIDC/UMA

  authorizeUrl(req: {
    clientId: string;
    redirectUri: string;
    state: string;
    pkce: { challenge: string; method: 'S256' };
  }) {
    const url = new URL(this.authorizeEndpoint());
    url.searchParams.set('client_id', req.clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid profile email');
    url.searchParams.set('redirect_uri', req.redirectUri);
    url.searchParams.set('state', req.state);
    url.searchParams.set('code_challenge', req.pkce.challenge);
    url.searchParams.set('code_challenge_method', req.pkce.method);
    return url.toString();
  }

  async tokenRequest(
    clientId: string,
    clientSecret: string | undefined, // <- opcional
    code: string,
    codeVerifier: string,
    redirectUri: string,
  ) {
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('client_id', clientId);
    if (clientSecret) body.set('client_secret', clientSecret);
    body.set('code', code);
    body.set('code_verifier', codeVerifier);
    body.set('redirect_uri', redirectUri);

    const { data } = await this.http.post(this.tokenEndpoint(), body);
    return data;
  }

  async logoutRequest(
    refreshToken: string,
    client?: { id?: string; secret?: string },
  ) {
    const body = new URLSearchParams();
    body.set('client_id', client?.id);
    const secret = client?.secret;
    if (secret) body.set('client_secret', secret);
    body.set('refresh_token', refreshToken);
    await this.http.post(this.logoutEndpoint(), body);
  }

  async umaRequest(req: {
    accessToken: string;
    audience: string;
    responseMode: 'permissions' | 'decision';
    permission?: string; // "resource#scope"
  }) {
    const body = new URLSearchParams();
    body.set('grant_type', 'urn:ietf:params:oauth:grant-type:uma-ticket');
    body.set('audience', req.audience);
    body.set('response_mode', req.responseMode);
    if (req.permission) body.set('permission', req.permission);

    const { data } = await this.http.post(this.tokenEndpoint(), body, {
      headers: { authorization: `Bearer ${req.accessToken}` },
    });
    return data;
  }

  async verifyAccessToken(
    token: string,
    expected?: { azp?: string; clockSkewSec?: number },
  ) {
    const { azp, clockSkewSec = 90 } = expected || {};
    const { payload, protectedHeader } = await jose.jwtVerify(
      token,
      this.jwks,
      {
        issuer: this.issuer(),
        algorithms: ['RS256', 'PS256'],
        clockTolerance: clockSkewSec,
      },
    );
    if (azp && payload.azp !== azp) {
      throw new Error(
        `azp inválido: se esperaba ${azp}, se obtuvo ${payload.azp}`,
      );
    }
    return { payload, header: protectedHeader };
  }
}
