/**
 * 存储工具
 */

import type { StorageAdapter, TokenStore, MultiAudienceTokenStore } from '@/types';
import { extractExp } from '@utils/paseto';

export const StorageKeys = {
  ACCESS_TOKEN: '###aegis@access-token###',
  ID_TOKEN: '###aegis@id-token###',
  REFRESH_TOKEN: '###aegis@refresh-token###',
  AUDIENCES: '###aegis@audiences###',
  CODE_VERIFIER: '###aegis@pkce-verifier###',
  STATE: '###aegis@flow-state###',
  AUDIENCE: '###aegis@flow-audience###',
  REDIRECT_URI: '###aegis@flow-redirect-uri###',
  MULTI_AUDIENCES: '###aegis@flow-audiences###',
  RETURN_TO: '###aegis@flow-return-to###',
} as const;

function scopedKey(base: string, scope: string): string {
  return base.replace(/###$/, `@${scope}###`);
}

export class BrowserStorageAdapter implements StorageAdapter {
  getItem(key: string): string | null {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  setItem(key: string, value: string): void {
    try { localStorage.setItem(key, value); } catch { /* noop */ }
  }
  removeItem(key: string): void {
    try { localStorage.removeItem(key); } catch { /* noop */ }
  }
}

export class MemoryStorageAdapter implements StorageAdapter {
  private store = new Map<string, string>();
  getItem(key: string): string | null { return this.store.get(key) ?? null; }
  setItem(key: string, value: string): void { this.store.set(key, value); }
  removeItem(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }
}

/**
 * Token 持久化管理，过期时间从 token payload 解析
 */
export class TokenStorage {
  constructor(private s: StorageAdapter) {}

  // ---- 默认 audience ----

  async persist(accessToken: string, refreshToken: string | null): Promise<void> {
    await Promise.resolve(this.s.setItem(StorageKeys.ACCESS_TOKEN, accessToken));
    if (refreshToken) {
      await Promise.resolve(this.s.setItem(StorageKeys.REFRESH_TOKEN, refreshToken));
    }
  }

  async load(): Promise<TokenStore> {
    const [accessToken, refreshToken] = await Promise.all([
      Promise.resolve(this.s.getItem(StorageKeys.ACCESS_TOKEN)),
      Promise.resolve(this.s.getItem(StorageKeys.REFRESH_TOKEN)),
    ]);
    return { accessToken, refreshToken };
  }

  async purge(): Promise<void> {
    await Promise.all([
      Promise.resolve(this.s.removeItem(StorageKeys.ACCESS_TOKEN)),
      Promise.resolve(this.s.removeItem(StorageKeys.REFRESH_TOKEN)),
    ]);
  }

  async expired(bufferMs = 5 * 60 * 1000): Promise<boolean> {
    const token = await Promise.resolve(this.s.getItem(StorageKeys.ACCESS_TOKEN));
    if (!token) return true;
    const exp = extractExp(token);
    return !exp || Date.now() + bufferMs >= exp.getTime();
  }

  // ---- scoped (per-audience) ----

  async persistScoped(audience: string, accessToken: string, refreshToken: string | null): Promise<void> {
    await Promise.resolve(this.s.setItem(scopedKey(StorageKeys.ACCESS_TOKEN, audience), accessToken));
    if (refreshToken) {
      await Promise.resolve(this.s.setItem(scopedKey(StorageKeys.REFRESH_TOKEN, audience), refreshToken));
    }
  }

  async loadScoped(audience: string): Promise<TokenStore> {
    const [accessToken, refreshToken] = await Promise.all([
      Promise.resolve(this.s.getItem(scopedKey(StorageKeys.ACCESS_TOKEN, audience))),
      Promise.resolve(this.s.getItem(scopedKey(StorageKeys.REFRESH_TOKEN, audience))),
    ]);
    return { accessToken, refreshToken };
  }

  async expiredScoped(audience: string, bufferMs = 5 * 60 * 1000): Promise<boolean> {
    const token = await Promise.resolve(this.s.getItem(scopedKey(StorageKeys.ACCESS_TOKEN, audience)));
    if (!token) return true;
    const exp = extractExp(token);
    return !exp || Date.now() + bufferMs >= exp.getTime();
  }

  async purgeScoped(audience: string): Promise<void> {
    await Promise.all([
      Promise.resolve(this.s.removeItem(scopedKey(StorageKeys.ACCESS_TOKEN, audience))),
      Promise.resolve(this.s.removeItem(scopedKey(StorageKeys.REFRESH_TOKEN, audience))),
    ]);
  }

  // ---- audience registry ----

  async registerAudiences(audiences: string[]): Promise<void> {
    await Promise.resolve(this.s.setItem(StorageKeys.AUDIENCES, JSON.stringify(audiences)));
  }

  audiences(): string[] {
    const raw = this.s.getItem(StorageKeys.AUDIENCES) as string | null;
    if (!raw) return [];
    try { return JSON.parse(raw); } catch { return []; }
  }

  async snapshot(): Promise<MultiAudienceTokenStore> {
    const result: MultiAudienceTokenStore = {};
    for (const aud of this.audiences()) {
      result[aud] = await this.loadScoped(aud);
    }
    return result;
  }

  async purgeAll(): Promise<void> {
    for (const aud of this.audiences()) {
      await this.purgeScoped(aud);
    }
    await Promise.resolve(this.s.removeItem(StorageKeys.AUDIENCES));
    await this.purge();
  }
}

/**
 * OAuth 一次性流程状态（authorize → callback 跨页面传递）
 */
export class FlowState {
  constructor(private s: StorageAdapter) {}

  async stashCodeVerifier(v: string): Promise<void> {
    await Promise.resolve(this.s.setItem(StorageKeys.CODE_VERIFIER, v));
  }
  popCodeVerifier(): string | null {
    return this.pop(StorageKeys.CODE_VERIFIER);
  }

  async stashState(v: string): Promise<void> {
    await Promise.resolve(this.s.setItem(StorageKeys.STATE, v));
  }
  popState(): string | null {
    return this.pop(StorageKeys.STATE);
  }

  async stashAudience(v: string): Promise<void> {
    await Promise.resolve(this.s.setItem(StorageKeys.AUDIENCE, v));
  }
  popAudience(): string | null {
    return this.pop(StorageKeys.AUDIENCE);
  }

  async stashRedirectUri(v: string): Promise<void> {
    await Promise.resolve(this.s.setItem(StorageKeys.REDIRECT_URI, v));
  }
  popRedirectUri(): string | null {
    return this.pop(StorageKeys.REDIRECT_URI);
  }

  async stashAudiences(v: Record<string, unknown>): Promise<void> {
    await Promise.resolve(this.s.setItem(StorageKeys.MULTI_AUDIENCES, JSON.stringify(v)));
  }
  popAudiences(): Record<string, unknown> | null {
    const raw = this.pop(StorageKeys.MULTI_AUDIENCES);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  async stashReturnTo(v: string): Promise<void> {
    await Promise.resolve(this.s.setItem(StorageKeys.RETURN_TO, v));
  }
  popReturnTo(): string | null {
    return this.pop(StorageKeys.RETURN_TO);
  }

  private pop(key: string): string | null {
    const v = this.s.getItem(key) as string | null;
    if (v) this.s.removeItem(key);
    return v;
  }
}
