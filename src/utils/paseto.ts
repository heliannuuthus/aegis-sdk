/**
 * PASETO v4.public token 工具
 */

import { verify as pasetoVerify } from 'paseto-ts/v4';
import type { HttpClient, IDTokenClaims, PublicKeysResponse } from '@/types';
import { AuthError, ErrorCodes } from '@/types';

function toUrlSafe(b64: string): string {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function toPaserk(base64Key: string): string {
  return `k4.public.${toUrlSafe(base64Key)}`;
}

let keyCache: { keys: string[]; ts: number } | null = null;
const KEY_TTL = 5 * 60 * 1000;

async function resolveKeys(
  endpoint: string,
  clientId: string,
  http: HttpClient
): Promise<string[]> {
  if (keyCache && Date.now() - keyCache.ts < KEY_TTL) {
    return keyCache.keys;
  }

  const res = await http.request<PublicKeysResponse>({
    method: 'GET',
    url: `${endpoint}/pubkeys?client_id=${encodeURIComponent(clientId)}`,
    headers: {},
  });

  if (res.status !== 200 || !res.data?.keys) {
    throw new AuthError(ErrorCodes.SERVER_ERROR, 'Failed to fetch public keys');
  }

  const keys = res.data.keys.map((k) => toPaserk(k.public_key));
  keyCache = { keys, ts: Date.now() };
  return keys;
}

/**
 * 验证 PASETO v4.public token，遍历所有公钥（支持密钥轮换）
 */
export async function verify(
  token: string,
  endpoint: string,
  clientId: string,
  http: HttpClient
): Promise<IDTokenClaims> {
  const keys = await resolveKeys(endpoint, clientId, http);

  for (const key of keys) {
    try {
      const { payload } = await pasetoVerify<IDTokenClaims>(key, token, {
        validatePayload: true,
      });
      return payload;
    } catch {
      continue;
    }
  }

  throw new AuthError(ErrorCodes.INVALID_TOKEN, 'No matching key for token verification');
}

export function invalidateKeys(): void {
  keyCache = null;
}

/**
 * 从 v4.public token 明文 payload 中提取 exp（无需验签）
 */
export function extractExp(token: string): Date | null {
  try {
    const parts = token.split('.');
    if (parts.length < 3 || parts[0] !== 'v4' || parts[1] !== 'public') return null;

    const decoded = atob(parts[2].replace(/-/g, '+').replace(/_/g, '/'));
    if (decoded.length < 64) return null;

    const { exp } = JSON.parse(decoded.slice(0, -64));
    return exp ? new Date(exp) : null;
  } catch {
    return null;
  }
}
