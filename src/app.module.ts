import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { CommonModule } from './common/common.module';
import { AuthAppMobileModule } from './auth-app-mobile/auth-app-mobile.module';
import { KeycloakModule } from './keycloak/keycloak.module';
import { SessionModule } from './session/session.module';

@Module({
  imports: [AuthModule, CommonModule, AuthAppMobileModule, KeycloakModule, SessionModule],
})
export class AppModule {}
