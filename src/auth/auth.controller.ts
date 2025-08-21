import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { EvaluatePermissionDto, LoginLdapAuthDto, ValidateTokenDto } from './dto'; 

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('ldap-auth.login')
  create(@Payload() loginLdapDto: LoginLdapAuthDto) {
    return this.authService.loginLdap(loginLdapDto);
  }

  @MessagePattern('ldap-auth.validateToken')
  validateToken(@Payload() dto: ValidateTokenDto ) {
    return this.authService.validateToken(dto);
  }
  
  @MessagePattern('ldap-auth.evaluatePermission')
  evaluatePermission(@Payload() dto: EvaluatePermissionDto) {
    return this.authService.evaluatePermission(dto);
  }
}
