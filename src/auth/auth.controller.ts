import { Controller } from '@nestjs/common';
import { MessagePattern, Payload, RpcException } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { LoginStartDto, LoginStartRes } from './dtos/login-start.dto';
import { LoginExchangeDto, LoginExchangeRes } from './dtos/login-exchange.dto';
import { SessionGetDto, SessionGetRes } from './dtos/session-get.dto';
import { VerifyTokenDto, VerifyTokenRes } from './dtos/verify-token.dto';
import { LogoutDto, LogoutRes } from './dtos/logout.dto';

@Controller()
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @MessagePattern('auth.login.start')
  async loginStart(@Payload() dto: LoginStartDto): Promise<LoginStartRes> {
    const { url, state } = await this.auth.buildAuthUrl(dto);
    return { ok: true, url, state };
  }

  // auth-service/src/auth/auth.controller.ts
  @MessagePattern('auth.login.exchange')
  async loginExchange(
    @Payload() dto: LoginExchangeDto,
  ): Promise<{ sid: string; returnTo: string }> {
    const { sid, returnTo } = await this.auth.exchangeCode(dto);
    return { sid, returnTo }; // ← sin “ok: true”
  }

  @MessagePattern('auth.session.get')
  async sessionGet(@Payload() dto: SessionGetDto): Promise<SessionGetRes> {
    try {
      const data = await this.auth.getSessionData(dto.sid, dto.clientId);
      return { ok: true, ...data };
    } catch (e: any) {
      // evita promesas colgadas
      throw new RpcException(e?.message ?? 'SESSION_LOOKUP_FAILED');
    }
  }

  @MessagePattern('auth.token.verify')
  async tokenVerify(@Payload() dto: VerifyTokenDto): Promise<VerifyTokenRes> {
    const vr = await this.auth.verifySessionAccessToken(dto.sid, dto.clientId);
    return {
      ok: true,
      isValid: vr.isValid,
      sub: vr.sub,
      exp: vr.exp,
      azp: vr.azp,
    };
  }

  @MessagePattern('auth.logout')
  async logout(@Payload() dto: LogoutDto): Promise<LogoutRes> {
    await this.auth.logout(dto.sid);
    return { ok: true };
  }
}
