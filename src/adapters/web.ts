/**
 * Web 浏览器适配器
 */

import type {
  AuthConfig,
  AudienceScope,
  IDTokenClaims,
} from '@/types';
import { Auth } from '@core/client';
import { BrowserStorageAdapter } from '@utils/storage';

/** WebAuth 构造配置（不变的参数） */
export interface WebAuthConfig {
  /** 认证服务器地址 */
  endpoint: string;
  /** 应用 Client ID */
  clientId: string;
  /** 默认重定向 URI */
  redirectUri?: string;
}

/** authorize 方法的参数（每次认证可变） */
export interface AuthorizeParams {
  /** 单 audience */
  audience?: string;
  /** 多 audience（优先于 audience） */
  audiences?: Record<string, AudienceScope>;
  /** scope 列表 */
  scopes: string[];
  /** 重定向 URI（覆盖 WebAuth 配置的 redirectUri） */
  redirectUri?: string;
  /** OIDC prompt 参数 */
  prompt?: string;
  /** 自定义 state */
  state?: string;
  /** 登录完成后跳转的路径（不传则自动保存当前路径） */
  returnTo?: string;
}

export class WebAuth {
  private auth: Auth;
  private config: WebAuthConfig;

  constructor(config: WebAuthConfig) {
    this.config = config;

    const authConfig: AuthConfig = {
      endpoint: config.endpoint,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      storage: new BrowserStorageAdapter(),
    };
    this.auth = new Auth(authConfig);
  }

  async authorize(params: AuthorizeParams): Promise<void> {
    const returnTo = params.returnTo ?? (window.location.pathname + window.location.search);
    await this.auth.saveReturnTo(returnTo);

    const audiences = params.audiences ?? undefined;
    const audience = audiences ? undefined : params.audience;

    const { url } = await this.auth.authorize({
      audience,
      audiences,
      scopes: params.scopes,
      state: params.state,
      redirectUri: params.redirectUri ?? this.config.redirectUri,
    });
    window.location.href = url;
  }

  async handleRedirectCallback(): Promise<{
    success: boolean;
    error?: string;
    redirectTo?: string;
  }> {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');
    const errorDescription = params.get('error_description');

    window.history.replaceState({}, '', window.location.pathname);

    if (error) {
      return { success: false, error: errorDescription || error };
    }
    if (!code) {
      return { success: false, error: 'No authorization code found' };
    }

    try {
      await this.auth.handleCallback(code, state ?? undefined);
      const savedPath = this.auth.consumeReturnTo();
      return { success: true, redirectTo: savedPath || '/' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  async getAccessToken(audience?: string): Promise<string | null> {
    return this.auth.getAccessToken(audience);
  }

  async getUser(): Promise<IDTokenClaims | null> {
    return this.auth.getUser();
  }

  audiences(): string[] {
    return this.auth.audiences();
  }

  async isAuthenticated(): Promise<boolean> {
    return this.auth.isAuthenticated();
  }

  async logout(options?: { returnTo?: string }): Promise<void> {
    await this.auth.logout();
    if (options?.returnTo) window.location.href = options.returnTo;
  }

  on: Auth['on'] = (...args) => this.auth.on(...args);
  off: Auth['off'] = (...args) => this.auth.off(...args);
}
