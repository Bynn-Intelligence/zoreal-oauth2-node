/**
 * Client authentication at the token endpoint. Four registrable methods:
 *
 *   none                 public client. No secret, no key; the form carries
 *                        client_id only and PKCE is the only proof. Tier A
 *                        scopes only, refused earlier (at /pair) otherwise.
 *   client_secret_basic  confidential. The secret travels as HTTP Basic
 *                        (client_id as user, secret as password), never as a
 *                        form field.
 *   private_key_jwt      confidential (RFC 7523). This package builds and
 *                        signs a fresh assertion per exchange from the
 *                        caller's private key; the provider verifies it
 *                        against the JWKS or certified key registered for the
 *                        client.
 *   tls_client_auth      mutual TLS at the transport. Registrable, but the
 *                        provider answers 501 "not implemented at this
 *                        endpoint yet" — the exchange surfaces that verbatim
 *                        rather than faking the method.
 */

import { KeyObject, createPrivateKey, randomUUID, type webcrypto } from 'node:crypto';
import { SignJWT } from 'jose';
import { ConfigurationError } from './errors';

/** A private key for private_key_jwt: a PEM string, a node KeyObject, or a WebCrypto CryptoKey. */
export type PrivateKeyInput = string | KeyObject | webcrypto.CryptoKey;

export type ClientAuth =
  | { method: 'none' }
  | { method: 'client_secret_basic'; clientSecret: string }
  | { method: 'private_key_jwt'; privateKey: PrivateKeyInput; kid?: string }
  | { method: 'tls_client_auth'; cert: string | Buffer; key: string | Buffer };

/**
 * The assertion the provider enforces: iss = sub = client_id, aud = the token
 * endpoint, exp at most 60 seconds out, iat no more than 60 seconds back, and
 * a fresh jti per assertion because the provider accepts each one exactly
 * once. P-256 signs ES256 (preferred: it matches the provider's certified-key
 * path); RSA signs RS256. Nothing else is accepted on either side.
 */
export async function buildClientAssertion(options: {
  clientId: string;
  tokenEndpoint: string;
  privateKey: PrivateKeyInput;
  kid?: string;
}): Promise<string> {
  const key = toSigningKey(options.privateKey);
  const alg = algorithmFor(key);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader(options.kid ? { alg, kid: options.kid } : { alg })
    .setIssuer(options.clientId)
    .setSubject(options.clientId)
    .setAudience(options.tokenEndpoint)
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .setJti(randomUUID())
    .sign(key);
}

function toSigningKey(privateKey: PrivateKeyInput): KeyObject | webcrypto.CryptoKey {
  if (typeof privateKey !== 'string') return privateKey;
  try {
    // createPrivateKey reads PKCS8, SEC1 and PKCS1 PEM alike.
    return createPrivateKey(privateKey);
  } catch {
    // The parse error is not propagated: OpenSSL's message can echo fragments
    // of the input, and a private key has no business inside an error.
    throw new ConfigurationError('the private_key_jwt PEM could not be parsed as a private key');
  }
}

function algorithmFor(key: KeyObject | webcrypto.CryptoKey): 'ES256' | 'RS256' {
  if (key instanceof KeyObject) {
    if (key.type !== 'private') {
      throw new ConfigurationError('private_key_jwt needs a private key, not a public one');
    }
    if (key.asymmetricKeyType === 'ec') {
      const curve = key.asymmetricKeyDetails?.namedCurve;
      if (curve !== 'prime256v1') {
        throw new ConfigurationError(
          `private_key_jwt EC keys must be P-256, not ${curve ?? 'an unknown curve'}`
        );
      }
      return 'ES256';
    }
    if (key.asymmetricKeyType === 'rsa') return 'RS256';
    throw new ConfigurationError(
      `private_key_jwt accepts P-256 (ES256) or RSA (RS256) keys, not ${key.asymmetricKeyType ?? 'this key type'}`
    );
  }

  const algorithm = key.algorithm as { name?: string; namedCurve?: string };
  if (algorithm.name === 'ECDSA') {
    if (algorithm.namedCurve !== 'P-256') {
      throw new ConfigurationError(
        `private_key_jwt EC keys must be P-256, not ${algorithm.namedCurve ?? 'an unknown curve'}`
      );
    }
    return 'ES256';
  }
  if (algorithm.name === 'RSASSA-PKCS1-v1_5') return 'RS256';
  throw new ConfigurationError(
    `private_key_jwt accepts P-256 (ES256) or RSA (RS256) keys, not ${algorithm.name ?? 'this key type'}`
  );
}
