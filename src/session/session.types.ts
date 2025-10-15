export type ClientTokenSet = {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
  roles?: string[];
};

export type SessionData = {
  tokenType: string;
  sub?: string;
  clients: Record<string, ClientTokenSet>;
};

export type PendingData = {
  codeVerifier: string;
  clientId: string;
  redirectUri: string;
  returnTo: string;
  createdAt: number;
};
