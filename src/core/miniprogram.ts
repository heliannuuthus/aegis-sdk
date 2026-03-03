/**
 * 小程序 Auth
 */

import type {
  AuthConfig,
  StorageAdapter,
  HttpClient,
  TokenResponse,
  AuthEvent,
  AuthEventListener,
  AuthEventType,
  IDPType,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { TokenStorage } from '@utils/storage';

export interface MPLoginParams {
  code: string;
  nickname?: string;
  avatar?: string;
}

export interface MPAuthConfig {
  issuer: string;
  idp: IDPType;
  storage: StorageAdapter;
  httpClient: HttpClient;
}

export class MiniProgramAuth {
  private config: MPAuthConfig;
  private tokens: TokenStorage;
  private listeners: Map<AuthEventType, Set<AuthEventListener>> = new Map();

  constructor(config: MPAuthConfig) {
    this.config = config;
    this.tokens = new TokenStorage(config.storage);
  }

  async login(params: MPLoginParams): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: `${this.config.idp}:${params.code}`,
    });
    if (params.nickname) body.append('nickname', params.nickname);
    if (params.avatar) body.append('avatar', params.avatar);

    const res = await this.config.httpClient.request<TokenResponse>({
      method: 'POST',
      url: `${this.config.issuer}/api/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.INVALID_GRANT, err?.error_description ?? 'Login failed');
    }

    await this.tokens.persist(res.data.access_token, res.data.refresh_token ?? null);
    this.emit('login', res.data);
    return res.data;
  }

  async getAccessToken(): Promise<string | null> {
    const store = await this.tokens.load();
    if (!store.accessToken) return null;

    if (await this.tokens.expired()) {
      if (store.refreshToken) {
        try {
          return (await this.refreshToken(store.refreshToken)).access_token;
        } catch {
          this.emit('token_expired');
          await this.tokens.purge();
          return null;
        }
      }
      this.emit('token_expired');
      await this.tokens.purge();
      return null;
    }

    return store.accessToken;
  }

  async refreshToken(refreshToken?: string): Promise<TokenResponse> {
    const rt = refreshToken ?? (await this.tokens.load()).refreshToken;
    if (!rt) throw new AuthError(ErrorCodes.NOT_AUTHENTICATED, 'No refresh token available');

    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt });
    const res = await this.config.httpClient.request<TokenResponse>({
      method: 'POST',
      url: `${this.config.issuer}/api/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (res.status !== 200) throw new AuthError(ErrorCodes.INVALID_GRANT, 'Token refresh failed');

    await this.tokens.persist(res.data.access_token, res.data.refresh_token ?? null);
    this.emit('token_refreshed', res.data);
    return res.data;
  }

  async logout(): Promise<void> {
    await this.tokens.purge();
    this.emit('logout');
  }

  async isAuthenticated(): Promise<boolean> {
    const store = await this.tokens.load();
    if (!store.accessToken) return false;
    if (await this.tokens.expired(60_000)) return !!store.refreshToken;
    return true;
  }

  on(event: AuthEventType, listener: AuthEventListener): () => void {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event)!.add(listener);
    return () => this.off(event, listener);
  }

  off(event: AuthEventType, listener: AuthEventListener): void {
    this.listeners.get(event)?.delete(listener);
  }

  private emit(type: AuthEventType, data?: unknown): void {
    const event: AuthEvent = { type, data };
    this.listeners.get(type)?.forEach((fn) => fn(event));
  }
}
