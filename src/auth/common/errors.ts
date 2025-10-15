export class InvalidInputError extends Error { code = 'INVALID_INPUT'; }
export class InvalidStateError extends Error { code = 'INVALID_STATE'; }
export class OriginNotAllowedError extends Error { code = 'ORIGIN_NOT_ALLOWED'; }
export class ClientNotAllowedError extends Error { code = 'CLIENT_NOT_ALLOWED'; }
export class TokenExchangeFailedError extends Error { code = 'TOKEN_EXCHANGE_FAILED'; }
export class SessionNotFoundError extends Error { code = 'SESSION_NOT_FOUND'; }
export class TokenInvalidError extends Error { code = 'TOKEN_INVALID'; }
export class LogoutFailedError extends Error { code = 'LOGOUT_FAILED'; }
