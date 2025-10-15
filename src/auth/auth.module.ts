import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { SecretEnvs } from 'src/config';
import { KeycloakModule } from 'src/keycloak/keycloak.module';
import { SessionModule } from 'src/session/session.module';

@Module({
  imports: [
    // PassportModule,
    // JwtModule.register({
    //   global: true,
    //   secret: SecretEnvs.jwtSecret,
    //   signOptions: { expiresIn: '4h' },
    // }),
    KeycloakModule,
    SessionModule
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
