import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { decodeJwt, decodeProtectedHeader, jwtVerify, generateKeyPair, exportJWK } from 'jose';
import { createLocalJWKSet } from 'jose';
import { ConfigurationError, ZorealOAuth2Client } from '../src';
import { CLIENT_ID, ISSUER, json, stubFetch, type FetchStub } from './helpers';

function pemP256(): string {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  }) as string;
}

function pemRsa(): string {
  return generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  }) as string;
}

async function assertionSentBy(client: ZorealOAuth2Client, fetch: FetchStub): Promise<string> {
  await client.exchange('code-1', 'verifier-1');
  const form = new URLSearchParams(String(fetch.callsTo('/token')[0].init?.body ?? ''));
  expect(form.get('client_assertion_type')).toBe(
    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  );
  const assertion = form.get('client_assertion');
  expect(assertion).toBeTruthy();
  return assertion as string;
}

describe('private_key_jwt', () => {
  it('builds an ES256 assertion with iss, sub, aud, exp, iat and jti correct', async () => {
    const fetch = stubFetch(() => json({ id_token: 'x' }));
    const client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      auth: { method: 'private_key_jwt', privateKey: pemP256(), kid: 'key-2026' },
      fetch,
    });

    const before = Math.floor(Date.now() / 1000);
    const assertion = await assertionSentBy(client, fetch);
    const after = Math.floor(Date.now() / 1000);

    const header = decodeProtectedHeader(assertion);
    expect(header.alg).toBe('ES256');
    expect(header.kid).toBe('key-2026');

    const claims = decodeJwt(assertion);
    expect(claims.iss).toBe(CLIENT_ID);
    expect(claims.sub).toBe(CLIENT_ID);
    expect(claims.aud).toBe(`${ISSUER}/token`);
    expect(claims.jti).toBeTruthy();
    expect(claims.iat).toBeGreaterThanOrEqual(before);
    expect(claims.iat).toBeLessThanOrEqual(after);
    // The provider caps the assertion at 60 seconds; the library uses exactly that.
    expect((claims.exp as number) - (claims.iat as number)).toBe(60);
  });

  it('signs with the key it claims: the assertion verifies against the public half', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const fetch = stubFetch(() => json({ id_token: 'x' }));
    const client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      // In the Node runtime jose's generated key is a KeyObject.
      auth: { method: 'private_key_jwt', privateKey: privateKey as KeyObject, kid: 'k' },
      fetch,
    });

    const assertion = await assertionSentBy(client, fetch);
    const jwks = createLocalJWKSet({
      keys: [{ ...(await exportJWK(publicKey)), kid: 'k', alg: 'ES256' }],
    });
    const { payload } = await jwtVerify(assertion, jwks, { audience: `${ISSUER}/token` });
    expect(payload.iss).toBe(CLIENT_ID);
  });

  it('mints a fresh jti per assertion: the provider accepts each exactly once', async () => {
    const fetch = stubFetch(() => json({ id_token: 'x' }));
    const client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      auth: { method: 'private_key_jwt', privateKey: pemP256() },
      fetch,
    });
    await client.exchange('code-1', 'verifier-1');
    await client.exchange('code-2', 'verifier-2');

    const jtis = fetch.callsTo('/token').map((call) => {
      const form = new URLSearchParams(String(call.init?.body ?? ''));
      return decodeJwt(form.get('client_assertion') as string).jti;
    });
    expect(jtis[0]).not.toBe(jtis[1]);
  });

  it('signs RS256 with an RSA key and omits kid when none is configured', async () => {
    const fetch = stubFetch(() => json({ id_token: 'x' }));
    const client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      auth: { method: 'private_key_jwt', privateKey: pemRsa() },
      fetch,
    });
    const header = decodeProtectedHeader(await assertionSentBy(client, fetch));
    expect(header.alg).toBe('RS256');
    expect(header.kid).toBeUndefined();
  });

  it('refuses an EC curve that is not P-256', async () => {
    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }) as string;
    const fetch = stubFetch(() => json({ id_token: 'x' }));
    const client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      auth: { method: 'private_key_jwt', privateKey: p384 },
      fetch,
    });
    await expect(client.exchange('code-1', 'verifier-1')).rejects.toBeInstanceOf(
      ConfigurationError
    );
  });

  it('refuses a PEM that is not a private key, without echoing it', async () => {
    const fetch = stubFetch(() => json({ id_token: 'x' }));
    const client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      auth: { method: 'private_key_jwt', privateKey: 'not a pem at all' },
      fetch,
    });
    const error = await client.exchange('code-1', 'verifier-1').catch((e: Error) => e);
    expect(error).toBeInstanceOf(ConfigurationError);
    expect(error.message).not.toContain('not a pem at all');
  });
});
