import axios from 'axios';
import * as jose from 'jose-node-cjs-runtime';
import { Injectable } from '@nestjs/common';
import { KeycloakEnvs } from '../config/envs';
import { VerifyResult } from './kc.types';

@Injectable()
export class KcJwksService {
  private jwks?: jose.JSONWebKeySet;
  private lastFetch = 0;

  private discoveryUrl() {
    return `${KeycloakEnvs.authServerUrl}/realms/${encodeURIComponent(KeycloakEnvs.realm)}/.well-known/openid-configuration`;
  }

  private async getJwksUri() {
    const { data } = await axios.get(this.discoveryUrl(), { timeout: 8000 });
    return data?.jwks_uri as string;
  }

  private async ensureJwks() {
    const now = Date.now();
    if (this.jwks && now - this.lastFetch < 5 * 60_000) return;
    const uri = await this.getJwksUri();
    const { data } = await axios.get(uri, { timeout: 8000 });
    this.jwks = data;
    this.lastFetch = now;
  }

  async verifyAccessToken(jwt: string, allowedClients: string[]): Promise<VerifyResult> {
    await this.ensureJwks();
    const keyStore = jose.createLocalJWKSet(this.jwks!);
    const { payload } = await jose.jwtVerify(jwt, keyStore, {
      issuer: `${KeycloakEnvs.authServerUrl}/realms/${KeycloakEnvs.realm}`,
    });
    const azp = payload.azp as string | undefined;
    if (azp && !allowedClients.includes(azp)) {
      return { isValid: false };
    }
    return { isValid: true, sub: payload.sub as string, exp: payload.exp as number, azp };
  }
}
