import { createLocalJWKSet, jwtVerify, errors as joseErrors } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { buildClientAssertion, type ClientAuth } from './auth';
import { ConfigurationError, ExchangeError, UserinfoError, VerificationError } from './errors';
import { Login } from './login';
import type { IdTokenClaims, TokenResponse, UserinfoClaims } from './types';

export const DEFAULT_ISSUER = 'https://id.zoreal.com';

/**
 * The provider serves its JWKS with a 10-minute public cache; mirroring it
 * here keeps a busy relying party off the endpoint without holding a
 * rotated-out key longer than the provider itself would.
 */
const JWKS_TTL_MS = 600_000;

/**
 * The transport seam. Node's built-in fetch by default; tests inject a stub
 * here, and every provider call — token, jwks, userinfo — goes through it.
 */
export type FetchLike = (
  url: string,
  init?: RequestInit & { dispatcher?: unknown }
) => Promise<Response>;

export interface ZorealOAuth2ClientOptions {
  /** The asset token from the ZOREAL dashboard, ast_... */
  clientId: string;
  /** Defaults to https://id.zoreal.com. Compared against `iss` exactly, never normalized. */
  issuer?: string;
  /** Defaults to { method: 'none' }: a public client, held by PKCE alone. */
  auth?: ClientAuth;
  /** Per-request timeout. Defaults to 10 seconds. */
  timeoutMs?: number;
  /** Replaces the transport for every provider call. The test seam. */
  fetch?: FetchLike;
}

/**
 * The relying-party client. One instance per registered ZOREAL client; it is
 * safe to share across concurrent requests, so build it once at boot.
 *
 *   const zoreal = new ZorealOAuth2Client({
 *     clientId: process.env.ZOREAL_CLIENT_ID,
 *     auth: { method: 'client_secret_basic', clientSecret: process.env.ZOREAL_CLIENT_SECRET },
 *   });
 *
 *   const login = await zoreal.authenticate(code, codeVerifier, nonce);
 *   login.sub               // the pairwise subject: your stable user key
 *   await login.userinfo()  // Tier B claims (email, name, ...), fetched once
 */
export class ZorealOAuth2Client {
  readonly clientId: string;
  readonly issuer: string;

  private readonly auth: ClientAuth;
  private readonly timeoutMs: number;
  private readonly fetchImpl?: FetchLike;
  private jwksCache: { keys: JSONWebKeySet; expiresAt: number } | null = null;
  private tlsTransport?: Promise<{ fetch: FetchLike; dispatcher: unknown }>;

  constructor(options: ZorealOAuth2ClientOptions) {
    if (isBlank(options?.clientId)) throw new ConfigurationError('clientId is required');
    const issuer = options.issuer ?? DEFAULT_ISSUER;
    if (isBlank(issuer)) throw new ConfigurationError('issuer is required');

    this.clientId = options.clientId;
    this.issuer = issuer.replace(/\/+$/, '');
    this.auth = options.auth ?? { method: 'none' };
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.fetchImpl = options.fetch;
    validateAuth(this.auth);
  }

  /**
   * The whole login, in order: exchange the code (with the PKCE verifier the
   * browser SDK handed over), verify the ID token against the JWKS, check the
   * nonce when the caller has it. Returns a Login; personal data is NOT
   * fetched here, because the ID token never carries it and not every caller
   * wants it — login.userinfo() fetches on first use.
   */
  async authenticate(code: string, codeVerifier: string, nonce?: string): Promise<Login> {
    const tokens = await this.exchange(code, codeVerifier);
    const claims = await this.verifyIdToken(tokens.id_token, nonce);
    return new Login({
      client: this,
      claims,
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      scope: tokens.scope,
    });
  }

  /**
   * POST /token. The verifier is mandatory: PKCE is required for every ZOREAL
   * client, and the browser SDK that generated it hands it to your frontend
   * precisely so your backend can present it here.
   */
  async exchange(code: string, codeVerifier: string): Promise<TokenResponse> {
    if (isBlank(code)) throw new TypeError('code is required');
    if (isBlank(codeVerifier)) throw new TypeError('code_verifier is required');

    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      code_verifier: codeVerifier,
      // Always present, whatever the auth method: the provider matches the
      // code against it.
      client_id: this.clientId,
    });
    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
    };

    if (this.auth.method === 'client_secret_basic') {
      // The secret travels as the Basic password, never as a form field.
      headers.authorization =
        'Basic ' + Buffer.from(`${this.clientId}:${this.auth.clientSecret}`).toString('base64');
    } else if (this.auth.method === 'private_key_jwt') {
      form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      form.set(
        'client_assertion',
        await buildClientAssertion({
          clientId: this.clientId,
          tokenEndpoint: `${this.issuer}/token`,
          privateKey: this.auth.privateKey,
          kid: this.auth.kid,
        })
      );
    }

    let response: Response;
    try {
      response = await this.request(`${this.issuer}/token`, {
        method: 'POST',
        headers,
        body: form.toString(),
      });
    } catch (error) {
      throw new ExchangeError(
        'server_error',
        `the token endpoint could not be reached: ${messageOf(error)}`
      );
    }

    const body = await parseJson(response);
    if (!response.ok) {
      throw new ExchangeError(
        stringOf(body.error) ?? 'server_error',
        stringOf(body.error_description) ?? `the provider answered ${response.status}`,
        response.status
      );
    }
    if (isBlank(body.id_token as string | undefined)) {
      throw new ExchangeError('server_error', 'no id_token in the token response', response.status);
    }
    return body as TokenResponse;
  }

  /**
   * ES256 against the provider's JWKS, plus iss (exact string equality), aud,
   * exp and — when the caller passes the nonce the SDK generated — the nonce
   * binding. Returns the claims. There is no RS256 fallback on purpose:
   * ZOREAL signs ID tokens with nothing else, and accepting a second
   * algorithm is how algorithm confusion starts.
   */
  async verifyIdToken(idToken: string, nonce?: string): Promise<IdTokenClaims> {
    if (isBlank(idToken)) throw new VerificationError('an ID token is required');

    let payload;
    try {
      payload = await this.verifyAgainst(await this.jwks(), idToken);
    } catch (error) {
      if (error instanceof joseErrors.JWKSNoMatchingKey) {
        // An unknown kid usually means the provider rotated inside our cache
        // window: invalidate and refetch, once.
        this.jwksCache = null;
        try {
          payload = await this.verifyAgainst(await this.jwks(), idToken);
        } catch (retryError) {
          throw asVerificationError(retryError);
        }
      } else {
        throw asVerificationError(error);
      }
    }

    if (!isBlank(nonce) && payload.nonce !== nonce) {
      throw new VerificationError('the ID token nonce is not the one this login started with');
    }
    return payload as IdTokenClaims;
  }

  /**
   * GET /userinfo with the Bearer access token from the exchange. This is the
   * only place personal claims (email, profile.*) are served, and the access
   * token lives ten minutes, so call it as part of handling the login rather
   * than storing the token for later.
   */
  async userinfo(accessToken: string): Promise<UserinfoClaims> {
    if (isBlank(accessToken)) throw new TypeError('access_token is required');

    let response: Response;
    try {
      response = await this.request(`${this.issuer}/userinfo`, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
    } catch (error) {
      throw new UserinfoError(`userinfo could not be reached: ${messageOf(error)}`);
    }

    const body = await parseJson(response);
    if (!response.ok) {
      throw new UserinfoError(
        stringOf(body.error_description) ?? `userinfo answered ${response.status}`,
        response.status
      );
    }
    return body as UserinfoClaims;
  }

  private async verifyAgainst(keys: JSONWebKeySet, idToken: string) {
    const { payload } = await jwtVerify(idToken, createLocalJWKSet(keys), {
      algorithms: ['ES256'],
      issuer: this.issuer,
      audience: this.clientId,
    });
    return payload;
  }

  private async jwks(): Promise<JSONWebKeySet> {
    const now = Date.now();
    if (this.jwksCache && this.jwksCache.expiresAt > now) return this.jwksCache.keys;

    let response: Response;
    try {
      response = await this.request(`${this.issuer}/jwks`);
    } catch (error) {
      throw new VerificationError(`could not fetch the provider JWKS: ${messageOf(error)}`);
    }
    if (!response.ok) {
      throw new VerificationError(`could not fetch the provider JWKS (${response.status})`);
    }

    const body = await parseJson(response);
    if (!Array.isArray(body.keys)) {
      throw new VerificationError('the provider JWKS was not a key set');
    }
    const keys = body as unknown as JSONWebKeySet;
    this.jwksCache = { keys, expiresAt: now + JWKS_TTL_MS };
    return keys;
  }

  private async request(url: string, init: RequestInit = {}): Promise<Response> {
    const { fetch: fetchImpl, dispatcher } = await this.transport();
    const withTimeout: Record<string, unknown> = {
      ...init,
      signal: AbortSignal.timeout(this.timeoutMs),
    };
    if (dispatcher) withTimeout.dispatcher = dispatcher;
    return fetchImpl(url, withTimeout as RequestInit);
  }

  private transport(): Promise<{ fetch: FetchLike; dispatcher?: unknown }> {
    // An injected fetch always wins, tls_client_auth included: whoever
    // replaced the transport owns the transport.
    if (this.fetchImpl) return Promise.resolve({ fetch: this.fetchImpl });
    if (this.auth.method !== 'tls_client_auth') {
      return Promise.resolve({ fetch: globalThis.fetch as unknown as FetchLike });
    }

    // Mutual TLS is transport configuration, so it needs undici's Agent and
    // undici's own fetch (the pair is guaranteed compatible). undici is an
    // optional peer dependency, loaded only on this path, so the other three
    // methods keep the install at one dependency.
    this.tlsTransport ??= (async () => {
      const auth = this.auth as Extract<ClientAuth, { method: 'tls_client_auth' }>;
      let undici: typeof import('undici');
      try {
        undici = await import('undici');
      } catch {
        throw new ConfigurationError(
          'tls_client_auth needs the optional undici package: npm install undici'
        );
      }
      const dispatcher = new undici.Agent({
        connect: { cert: auth.cert, key: auth.key },
      });
      return { fetch: undici.fetch as unknown as FetchLike, dispatcher };
    })();
    return this.tlsTransport;
  }
}

function validateAuth(auth: ClientAuth): void {
  switch (auth.method) {
    case 'none':
      return;
    case 'client_secret_basic':
      if (isBlank(auth.clientSecret)) {
        throw new ConfigurationError('client_secret_basic needs a clientSecret');
      }
      return;
    case 'private_key_jwt':
      if (auth.privateKey == null || (typeof auth.privateKey === 'string' && isBlank(auth.privateKey))) {
        throw new ConfigurationError('private_key_jwt needs a privateKey');
      }
      return;
    case 'tls_client_auth':
      if (auth.cert == null || auth.key == null) {
        throw new ConfigurationError('tls_client_auth needs a cert and a key');
      }
      return;
    default:
      throw new ConfigurationError(
        `unknown client authentication method ${(auth as { method: string }).method}`
      );
  }
}

function asVerificationError(error: unknown): Error {
  if (error instanceof VerificationError) return error;
  // jose's messages name the failed check and never quote the token.
  if (error instanceof joseErrors.JOSEError) return new VerificationError(error.message);
  return error instanceof Error ? error : new VerificationError(String(error));
}

async function parseJson(response: Response): Promise<Record<string, unknown>> {
  try {
    const parsed: unknown = JSON.parse(await response.text());
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function messageOf(error: unknown): string {
  if (error instanceof Error) {
    // Node's fetch says "fetch failed" and hides the reason in cause.
    if (error.cause instanceof Error) return error.cause.message;
    return error.message;
  }
  return String(error);
}

function stringOf(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function isBlank(value: string | undefined | null): boolean {
  return value == null || value.trim() === '';
}
