import { Module } from '@nestjs/common';
import { KeycloakClientService } from './keycloak-client.service';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [HttpModule],
  providers: [KeycloakClientService],
  exports: [KeycloakClientService],
})
export class KeycloakModule {}
