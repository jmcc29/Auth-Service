import { randomId, sha256Base64Url } from './crypto.util';

export function generatePkce() {
  const verifier = randomId(32);
  const challenge = sha256Base64Url(verifier);
  return { verifier, challenge };
}
