import { Injectable, UnauthorizedException } from '@nestjs/common';
import { jwtVerify, createRemoteJWKSet } from 'jose-node-cjs-runtime';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { KeycloakEnvs as keycloak} from 'src/config/envs';

@Injectable()
export class KeycloakClientService {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private readonly issuer: string;
  private readonly expectedAzp: string;
  private readonly defaultHeaders = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  //private audience: string;

  constructor(
    private readonly http: HttpService
  ) {
    if (!keycloak.issuer) {
      throw new Error('Keycloak issuer is not defined');
    }
    this.issuer = keycloak.issuer;
    this.expectedAzp = keycloak.clientId;
    this.jwks = createRemoteJWKSet(
      new URL(keycloak.endpoint.certs),
    );
  }

  async getToken(username: string, password: string) {
    const body = new URLSearchParams({
      client_id: keycloak.clientId,
      grant_type: 'password',
      username,
      password,
      scope: 'openid',
      client_secret: keycloak.clientSecret,
    });

    const res = await firstValueFrom(
      this.http.post(keycloak.endpoint.token, body.toString(), {
        headers: this.defaultHeaders,
      }),
    );

    return res.data;
  }

  async validateToken(token: string) {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        // audience: this.audience,
      });
      //Validación explicita del azp (Authorized Party) esto viene reemplazando la validacion de audience
      if (payload.azp !== this.expectedAzp) {
        throw new UnauthorizedException('Token emitido por otro cliente');
      }
      return {
        isValid: true,
        user: {
          sub: payload.sub,
          username: payload.preferred_username,
          email: payload.email,
          name: payload.name,
          //   realmRoles: payload.realm_access?.roles ?? [],
          // clientRoles: payload.resource_access?.[envs.keycloak.clientId]?.roles ?? [],
        },
      };
    } catch (err) {
      console.error('[KeycloakClientService] Token inválido:', err.message);
      return { isValid: false };
    }
  }
  
  async evaluatePermission(accessToken: string, resource: string, scope: string): Promise<boolean> {
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
      audience: keycloak.clientId,
      response_mode: 'decision',
      permission: `${resource}#${scope}`,
    });

    try {
      const res = await firstValueFrom(
        this.http.post(keycloak.endpoint.token, body.toString(), {
          headers: {
            ...this.defaultHeaders,
            Authorization: `Bearer ${accessToken}`,
          },
        }),
      );

      return res.data?.result === true;
    } catch (error) {
      console.error('[KeycloakClientService] evaluatePermission error:', error?.response?.data || error.message);
      return false;
    }
  }

}
