import { Global, Module } from '@nestjs/common';
import { KcJwksService } from './kc-jwks.service';

@Global()
@Module({
  providers: [KcJwksService],
  exports: [KcJwksService],
})
export class KeycloakModule {}
