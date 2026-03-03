/**
 * @aegis/sdk
 * Aegis Auth SDK - 支持 Web 和小程序的认证 SDK
 */

// ==================== 核心类 ====================
export { Auth } from '@core/client';
export { MiniProgramAuth } from '@core/miniprogram';
export type { MPLoginParams, MPAuthConfig } from '@core/miniprogram';

// ==================== 类型 ====================
export type {
  AuthConfig,
  AuthorizeOptions,
  StorageAdapter,
  HttpClient,
  HttpRequestConfig,
  HttpResponse,
  TokenResponse,
  TokenStore,
  // Multi-audience
  AudienceScope,
  MultiAudienceTokenResponse,
  MultiAudienceTokenStore,
  // ID Token
  IDTokenClaims,
  PublicKeyInfo,
  PublicKeysResponse,
  // User
  UserInfo,
  PKCEParams,
  IDPType,
  GrantType,
  CodeChallengeMethod,
  AuthEvent,
  AuthEventType,
  AuthEventListener,
  // Connections
  ConnectionConfig,
  RequireConfig,
  DelegateConfig,
  VChanConfig,
  ConnectionsResponse,
  // Challenge
  ChallengeType,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  // Login
  LoginRequest,
} from '@/types';

export { AuthError, ErrorCodes } from '@/types';

// ==================== 工具函数 ====================
export { generatePKCE, generateCodeVerifier, generateCodeChallenge, isValidCodeVerifier } from '@utils/pkce';
export { BrowserStorageAdapter, MemoryStorageAdapter, TokenStorage, FlowState, StorageKeys } from '@utils/storage';

// ==================== 版本 ====================
export const VERSION = '1.0.0';
