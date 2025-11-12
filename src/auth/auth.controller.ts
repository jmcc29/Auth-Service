import { Controller } from '@nestjs/common';
import { MessagePattern, Payload, RpcException } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import {
  LoginStartDto,
  LoginStartRes,
  LoginExchangeDto,
  SessionGetDto,
  SessionGetRes,
  VerifyTokenDto,
  VerifyTokenRes,
  LogoutDto,
  LogoutRes,
  ProfileGetDto,
  ProfileGetRes,
  PermissionEvaluateDto,
  PermissionEvaluateRes,
  PermissionsListDto,
  PermissionsListRes,
} from './dtos';

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

  // @MessagePattern('auth.profile.get')
  // async profileGet(@Payload() dto: ProfileGetDto): Promise<ProfileGetRes> {
  //   try {
  //     return await this.auth.getProfile(dto.sid, dto.clientId);
  //   } catch (e: any) {
  //     throw new RpcException(e?.message ?? 'PROFILE_LOOKUP_FAILED');
  //   }
  // }
  @MessagePattern('auth.profile.get')
  async profileGet(@Payload() dto: ProfileGetDto): Promise<ProfileGetRes> {
    try {
      return await this.auth.getProfileByCtx(dto.sid, {
        clientId: dto.clientId,
        origin: dto.origin,
        referer: dto.referer,
      });
    } catch (e: any) {
      throw new RpcException(e?.message ?? 'PROFILE_LOOKUP_FAILED');
    }
  }
  @MessagePattern('auth.permissions.list')
  async permissionsList(
    @Payload() dto: PermissionsListDto,
  ): Promise<PermissionsListRes> {
    try {
      const permissions = await this.auth.listPermissionsByCtx(dto.sid, {
        audience: dto.audience,
        clientId: dto.clientId,
        origin: dto.origin,
        referer: dto.referer,
      });
      return { ok: true, audience: dto.audience, permissions };
    } catch (e: any) {
      throw new RpcException(e?.message ?? 'PERMISSIONS_LIST_FAILED');
    }
  }

  @MessagePattern('auth.permission.evaluate')
  async permissionEvaluate(
    @Payload() dto: PermissionEvaluateDto,
  ): Promise<PermissionEvaluateRes> {
    try {
      const allowed = await this.auth.evaluatePermissionByCtx(dto.sid, {
        audience: dto.audience,
        resource: dto.resource,
        scope: dto.scope,
        clientId: dto.clientId,
        origin: dto.origin,
        referer: dto.referer,
      });
      return {
        ok: true,
        audience: dto.audience,
        resource: dto.resource,
        scope: dto.scope,
        allowed,
      };
    } catch (e: any) {
      throw new RpcException(e?.message ?? 'PERMISSION_EVALUATE_FAILED');
    }
  }

}
