/**
 * Offline test scaffolding: a P-256 keypair generated per suite, its public
 * half exported as the JWKS the stubbed transport serves, and a router-style
 * fetch stub that records every call. Nothing in the suite touches the
 * network.
 */

import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import type { JWTPayload, KeyLike } from 'jose';

export const ISSUER = 'https://id.zoreal.example';
export const CLIENT_ID = 'ast_test_client';

export interface TestKeys {
  privateKey: KeyLike;
  jwks: { keys: Record<string, unknown>[] };
  kid: string;
}

export async function makeKeys(kid = 'test-key-1'): Promise<TestKeys> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, use: 'sig', alg: 'ES256' };
  return { privateKey, jwks: { keys: [jwk] }, kid };
}

export function baseClaims(overrides: Record<string, unknown> = {}): JWTPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    sub: '7QK3-9F2M-XR84-B5NP',
    aud: CLIENT_ID,
    exp: now + 120,
    iat: now,
    nonce: 'n-1',
    acr: 'zoreal.device',
    ...overrides,
  };
}

export async function sign(claims: JWTPayload, privateKey: KeyLike, kid: string): Promise<string> {
  return new SignJWT(claims).setProtectedHeader({ alg: 'ES256', kid }).sign(privateKey);
}

export interface RecordedCall {
  url: string;
  init?: RequestInit & { dispatcher?: unknown };
}

export type StubHandler = (
  url: string,
  init?: RequestInit & { dispatcher?: unknown }
) => Response | Promise<Response>;

export interface FetchStub {
  (url: string, init?: RequestInit & { dispatcher?: unknown }): Promise<Response>;
  calls: RecordedCall[];
  callsTo(path: string): RecordedCall[];
}

export function stubFetch(handler: StubHandler): FetchStub {
  const calls: RecordedCall[] = [];
  const stub = (async (url: string, init?: RequestInit & { dispatcher?: unknown }) => {
    calls.push({ url, init });
    return handler(url, init);
  }) as FetchStub;
  stub.calls = calls;
  stub.callsTo = (path: string) => calls.filter((call) => new URL(call.url).pathname === path);
  return stub;
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** A stub that only knows how to serve the JWKS; anything else is a test bug. */
export function jwksOnlyFetch(keys: TestKeys): FetchStub {
  return stubFetch((url) => {
    if (new URL(url).pathname === '/jwks') return json(keys.jwks);
    throw new Error(`unexpected request to ${new URL(url).pathname}`);
  });
}
