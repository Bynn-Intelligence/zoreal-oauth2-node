import { describe, expect, it } from 'vitest';
import { ExchangeError, ZorealOAuth2Client } from '../src';
import {
  CLIENT_ID,
  ISSUER,
  baseClaims,
  json,
  makeKeys,
  sign,
  stubFetch,
} from './helpers';

const SECRET = 'zcs_test_secret';

function formOf(init?: { body?: unknown }): URLSearchParams {
  return new URLSearchParams(String(init?.body ?? ''));
}

function headerOf(init: { headers?: unknown } | undefined, name: string): string | undefined {
  return (init?.headers as Record<string, string> | undefined)?.[name];
}

describe('exchange', () => {
  it('posts the form for a public client: client_id and PKCE, no credentials anywhere', async () => {
    const fetch = stubFetch(() => json({ id_token: 'x' }));
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });
    await client.exchange('code-1', 'verifier-1');

    const call = fetch.callsTo('/token')[0];
    const form = formOf(call.init);
    expect(form.get('grant_type')).toBe('authorization_code');
    expect(form.get('code')).toBe('code-1');
    expect(form.get('code_verifier')).toBe('verifier-1');
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.has('client_secret')).toBe(false);
    expect(form.has('client_assertion')).toBe(false);
    expect(headerOf(call.init, 'authorization')).toBeUndefined();
  });

  it('sends client_secret_basic as HTTP Basic, never as a form field', async () => {
    const fetch = stubFetch(() => json({ id_token: 'x' }));
    const client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      auth: { method: 'client_secret_basic', clientSecret: SECRET },
      fetch,
    });
    await client.exchange('code-1', 'verifier-1');

    const call = fetch.callsTo('/token')[0];
    const expected = 'Basic ' + Buffer.from(`${CLIENT_ID}:${SECRET}`).toString('base64');
    expect(headerOf(call.init, 'authorization')).toBe(expected);
    const form = formOf(call.init);
    // The form still carries client_id: the provider matches the code against it.
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.has('client_secret')).toBe(false);
  });

  it('maps a provider refusal to an ExchangeError carrying code, reason and status', async () => {
    const fetch = stubFetch(() =>
      json({ error: 'invalid_grant', error_description: 'the code is not valid' }, 400)
    );
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });

    const error = await client.exchange('code-1', 'verifier-1').catch((e: ExchangeError) => e);
    expect(error).toBeInstanceOf(ExchangeError);
    expect(error.oauthError).toBe('invalid_grant');
    expect(error.description).toBe('the code is not valid');
    expect(error.status).toBe(400);
    expect(error.message).toBe('invalid_grant: the code is not valid');
  });

  it('maps a non-JSON provider failure to server_error with the status', async () => {
    const fetch = stubFetch(() => new Response('Bad Gateway', { status: 502 }));
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });

    const error = await client.exchange('code-1', 'verifier-1').catch((e: ExchangeError) => e);
    expect(error).toBeInstanceOf(ExchangeError);
    expect(error.oauthError).toBe('server_error');
    expect(error.description).toBe('the provider answered 502');
    expect(error.status).toBe(502);
  });

  it('refuses a success response with no id_token', async () => {
    const fetch = stubFetch(() => json({ access_token: 'a', token_type: 'Bearer' }));
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });
    await expect(client.exchange('code-1', 'verifier-1')).rejects.toThrow(
      'no id_token in the token response'
    );
  });

  it('wraps an unreachable token endpoint as an ExchangeError', async () => {
    const fetch = stubFetch(() => {
      throw new TypeError('fetch failed', { cause: new Error('ECONNREFUSED') });
    });
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });
    const error = await client.exchange('code-1', 'verifier-1').catch((e: ExchangeError) => e);
    expect(error).toBeInstanceOf(ExchangeError);
    expect(error.message).toContain('ECONNREFUSED');
    expect(error.status).toBeUndefined();
  });

  it('surfaces the provider 501 for tls_client_auth as the exchange error it is', async () => {
    const fetch = stubFetch(() =>
      json(
        {
          error: 'invalid_request',
          error_description:
            'tls_client_auth is not implemented at this endpoint yet; use private_key_jwt or client_secret_basic',
        },
        501
      )
    );
    const client = new ZorealOAuth2Client({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      auth: { method: 'tls_client_auth', cert: 'CERT PEM', key: 'KEY PEM' },
      fetch,
    });

    const error = await client.exchange('code-1', 'verifier-1').catch((e: ExchangeError) => e);
    expect(error).toBeInstanceOf(ExchangeError);
    expect(error.status).toBe(501);
    expect(error.description).toContain('not implemented at this endpoint yet');
  });
});

describe('authenticate', () => {
  it('exchanges, verifies and returns a Login without touching userinfo', async () => {
    const keys = await makeKeys();
    const idToken = await sign(
      baseClaims({ nonce: 'n-42', age_over_18: true }),
      keys.privateKey,
      keys.kid
    );
    const fetch = stubFetch((url) => {
      switch (new URL(url).pathname) {
        case '/token':
          return json({
            id_token: idToken,
            access_token: 'zat_test',
            token_type: 'Bearer',
            expires_in: 600,
            scope: 'openid zoreal.age',
          });
        case '/jwks':
          return json(keys.jwks);
        default:
          throw new Error(`unexpected request to ${url}`);
      }
    });
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });

    const login = await client.authenticate('code-1', 'verifier-1', 'n-42');
    expect(login.sub).toBe('7QK3-9F2M-XR84-B5NP');
    expect(login.ageOver(18)).toBe(true);
    expect(login.accessToken).toBe('zat_test');
    expect(login.scope).toBe('openid zoreal.age');
    expect(fetch.callsTo('/userinfo')).toHaveLength(0);
  });

  it('refuses a substituted ID token: the nonce is checked against the exchange', async () => {
    const keys = await makeKeys();
    const idToken = await sign(baseClaims({ nonce: 'stolen' }), keys.privateKey, keys.kid);
    const fetch = stubFetch((url) =>
      new URL(url).pathname === '/token' ? json({ id_token: idToken }) : json(keys.jwks)
    );
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });
    await expect(client.authenticate('code-1', 'verifier-1', 'n-42')).rejects.toThrow(
      'nonce is not the one this login started with'
    );
  });
});
