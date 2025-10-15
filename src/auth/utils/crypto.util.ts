import * as crypto from 'crypto';

export function randomId(bytes = 24): string {
  return base64Url(crypto.randomBytes(bytes));
}
export function base64Url(buf: Buffer): string {
  try { return buf.toString('base64url'); }
  catch {
    return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
}
export function sha256Base64Url(input: string): string {
  return base64Url(crypto.createHash('sha256').update(input).digest());
}
