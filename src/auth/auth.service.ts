import { Injectable } from '@nestjs/common';
import {
  EvaluatePermissionDto,
  LoginLdapAuthDto,
  ValidateTokenDto,
} from './dto';
import { KeycloakClientService } from 'src/keycloak/keycloak-client.service';

@Injectable()
export class AuthService {
  constructor(private readonly keycloakClient: KeycloakClientService) {}
  loginLdap(loginLdapDto: LoginLdapAuthDto) {
    const { username, password } = loginLdapDto;
    return this.keycloakClient.getToken(username, password);
  }
  async validateToken(accessToken: ValidateTokenDto) {
    return this.keycloakClient.validateToken(accessToken.accessToken);
  }
  async evaluatePermission({
    accessToken,
    resource,
    scope,
  }: EvaluatePermissionDto) {
    return this.keycloakClient.evaluatePermission(accessToken, resource, scope);
  }
}
