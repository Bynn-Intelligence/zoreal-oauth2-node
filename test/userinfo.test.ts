import { describe, expect, it } from 'vitest';
import { UserinfoError, ZorealOAuth2Client } from '../src';
import { CLIENT_ID, ISSUER, json, stubFetch } from './helpers';

describe('userinfo', () => {
  it('sends the Bearer token and returns the claims', async () => {
    const fetch = stubFetch(() =>
      json({ sub: '7QK3-9F2M-XR84-B5NP', email: 'holder@example.com', email_verified: true })
    );
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });

    const claims = await client.userinfo('zat_test');
    expect(claims.email).toBe('holder@example.com');
    const call = fetch.callsTo('/userinfo')[0];
    expect((call.init?.headers as Record<string, string>).authorization).toBe('Bearer zat_test');
  });

  it('maps a refusal to a UserinfoError carrying the provider reason and status', async () => {
    const fetch = stubFetch(() =>
      json({ error: 'invalid_token', error_description: 'the access token is not valid' }, 401)
    );
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });

    const error = await client.userinfo('zat_expired').catch((e: UserinfoError) => e);
    expect(error).toBeInstanceOf(UserinfoError);
    expect(error.message).toBe('the access token is not valid');
    expect(error.status).toBe(401);
    // The rule that holds everywhere: the token never appears in the message.
    expect(error.message).not.toContain('zat_expired');
  });

  it('falls back to the status when the refusal body carries no description', async () => {
    const fetch = stubFetch(() => new Response('', { status: 500 }));
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });
    await expect(client.userinfo('zat_test')).rejects.toThrow('userinfo answered 500');
  });

  it('wraps an unreachable endpoint as a UserinfoError', async () => {
    const fetch = stubFetch(() => {
      throw new TypeError('fetch failed', { cause: new Error('ECONNREFUSED') });
    });
    const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });
    await expect(client.userinfo('zat_test')).rejects.toBeInstanceOf(UserinfoError);
  });
});
