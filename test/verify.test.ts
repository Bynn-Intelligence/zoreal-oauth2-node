import { describe, expect, it, beforeEach } from 'vitest';
import { generateKeyPair } from 'jose';
import { ConfigurationError, VerificationError, ZorealOAuth2Client } from '../src';
import {
  CLIENT_ID,
  ISSUER,
  baseClaims,
  json,
  jwksOnlyFetch,
  makeKeys,
  sign,
  stubFetch,
  type TestKeys,
  type FetchStub,
} from './helpers';

describe('verifyIdToken', () => {
  let keys: TestKeys;
  let fetch: FetchStub;
  let client: ZorealOAuth2Client;

  beforeEach(async () => {
    keys = await makeKeys();
    fetch = jwksOnlyFetch(keys);
    client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });
  });

  it('verifies a valid ES256 token and returns the claims', async () => {
    const claims = await client.verifyIdToken(await sign(baseClaims(), keys.privateKey, keys.kid), 'n-1');
    expect(claims.sub).toBe('7QK3-9F2M-XR84-B5NP');
    expect(claims.acr).toBe('zoreal.device');
  });

  it('fetches the JWKS once and serves the second verification from cache', async () => {
    await client.verifyIdToken(await sign(baseClaims(), keys.privateKey, keys.kid));
    await client.verifyIdToken(await sign(baseClaims(), keys.privateKey, keys.kid));
    expect(fetch.callsTo('/jwks')).toHaveLength(1);
  });

  it('refuses a nonce mismatch', async () => {
    const token = await sign(baseClaims(), keys.privateKey, keys.kid);
    await expect(client.verifyIdToken(token, 'other')).rejects.toBeInstanceOf(VerificationError);
  });

  it('does not check the nonce when the caller has none', async () => {
    const token = await sign(baseClaims(), keys.privateKey, keys.kid);
    await expect(client.verifyIdToken(token)).resolves.toBeTruthy();
  });

  it('refuses the wrong audience', async () => {
    const token = await sign(baseClaims({ aud: 'ast_other' }), keys.privateKey, keys.kid);
    await expect(client.verifyIdToken(token)).rejects.toBeInstanceOf(VerificationError);
  });

  it('refuses the wrong issuer', async () => {
    const token = await sign(
      baseClaims({ iss: 'https://evil.example' }),
      keys.privateKey,
      keys.kid
    );
    await expect(client.verifyIdToken(token)).rejects.toBeInstanceOf(VerificationError);
  });

  it('refuses an expired token', async () => {
    const token = await sign(
      baseClaims({ exp: Math.floor(Date.now() / 1000) - 5 }),
      keys.privateKey,
      keys.kid
    );
    await expect(client.verifyIdToken(token)).rejects.toBeInstanceOf(VerificationError);
  });

  it('refuses a foreign key under an unknown kid, refetching the JWKS exactly once', async () => {
    const foreign = await makeKeys('foreign-key');
    const token = await sign(baseClaims(), foreign.privateKey, foreign.kid);
    await expect(client.verifyIdToken(token)).rejects.toBeInstanceOf(VerificationError);
    // Unknown kid invalidates the cache and refetches once; it does not loop.
    expect(fetch.callsTo('/jwks')).toHaveLength(2);
  });

  it('refuses a foreign key hiding under a known kid', async () => {
    const foreign = await makeKeys(keys.kid);
    const token = await sign(baseClaims(), foreign.privateKey, foreign.kid);
    await expect(client.verifyIdToken(token)).rejects.toBeInstanceOf(VerificationError);
  });

  it('refuses any algorithm that is not ES256', async () => {
    // An unsigned token, alg none: the classic downgrade. Refused before any
    // key is even looked up.
    const encode = (part: object) =>
      Buffer.from(JSON.stringify(part)).toString('base64url');
    const unsigned = `${encode({ alg: 'none' })}.${encode(baseClaims())}.`;
    await expect(client.verifyIdToken(unsigned)).rejects.toBeInstanceOf(VerificationError);

    // RS256 with a real RSA signature: also refused, never negotiated.
    const rsa = await generateKeyPair('RS256');
    const { SignJWT } = await import('jose');
    const rs256 = await new SignJWT(baseClaims())
      .setProtectedHeader({ alg: 'RS256', kid: keys.kid })
      .sign(rsa.privateKey);
    await expect(client.verifyIdToken(rs256)).rejects.toBeInstanceOf(VerificationError);
  });

  it('surfaces an unreachable JWKS endpoint as a VerificationError', async () => {
    const down = stubFetch(() => {
      throw new TypeError('fetch failed');
    });
    const offline = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch: down });
    const token = await sign(baseClaims(), keys.privateKey, keys.kid);
    await expect(offline.verifyIdToken(token)).rejects.toBeInstanceOf(VerificationError);
  });

  it('surfaces a JWKS endpoint error status as a VerificationError', async () => {
    const broken = stubFetch(() => json({}, 503));
    const offline = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch: broken });
    const token = await sign(baseClaims(), keys.privateKey, keys.kid);
    await expect(offline.verifyIdToken(token)).rejects.toThrow(/JWKS \(503\)/);
  });

  it('never quotes the token in a verification error', async () => {
    const token = await sign(baseClaims({ aud: 'ast_other' }), keys.privateKey, keys.kid);
    const error = await client.verifyIdToken(token).catch((e: Error) => e);
    expect(error).toBeInstanceOf(VerificationError);
    expect((error as Error).message).not.toContain(token.slice(0, 20));
  });
});

// The assurance floor at verification: the acr_values the frontend sent were
// advisory, the signed acr claim is the proof, and this is the check.
describe('the assurance floor (acr)', () => {
  let keys: TestKeys;
  let client: ZorealOAuth2Client;

  beforeEach(async () => {
    keys = await makeKeys();
    client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      fetch: jwksOnlyFetch(keys),
    });
  });

  // A token whose acr is exactly the given value; no acr claim at all when
  // called without one (an undefined override serializes to nothing).
  function token(acr?: string): Promise<string> {
    return sign(baseClaims({ acr }), keys.privateKey, keys.kid);
  }

  it('an equal acr satisfies', async () => {
    await expect(
      client.verifyIdToken(await token('zoreal.live'), { acr: 'zoreal.live' })
    ).resolves.toBeTruthy();
  });

  it('a stronger acr satisfies', async () => {
    await expect(
      client.verifyIdToken(await token('zoreal.live'), { acr: 'zoreal.device' })
    ).resolves.toBeTruthy();
  });

  it('a weaker acr is refused, naming both values and never the token', async () => {
    const jwt = await token('zoreal.device');
    const error = await client
      .verifyIdToken(jwt, { acr: 'zoreal.live' })
      .catch((e: Error) => e);
    expect(error).toBeInstanceOf(VerificationError);
    expect((error as Error).message).toContain('zoreal.device');
    expect((error as Error).message).toContain('zoreal.live');
    expect((error as Error).message).not.toContain(jwt.slice(0, 20));
  });

  it('a missing acr is refused when one is required', async () => {
    await expect(
      client.verifyIdToken(await token(), { acr: 'zoreal.session' })
    ).rejects.toBeInstanceOf(VerificationError);
  });

  it('an unknown REQUIRED acr is a ConfigurationError: a caller typo, not a bad token', async () => {
    await expect(
      client.verifyIdToken(await token('zoreal.live'), { acr: 'zoreal.liveness' })
    ).rejects.toBeInstanceOf(ConfigurationError);
  });

  it('no required acr checks nothing', async () => {
    await expect(client.verifyIdToken(await token())).resolves.toBeTruthy();
  });

  it('the nonce rides along in the options form', async () => {
    const jwt = await token('zoreal.live');
    await expect(
      client.verifyIdToken(jwt, { nonce: 'n-1', acr: 'zoreal.live' })
    ).resolves.toBeTruthy();
    await expect(
      client.verifyIdToken(jwt, { nonce: 'other', acr: 'zoreal.live' })
    ).rejects.toBeInstanceOf(VerificationError);
  });
});
