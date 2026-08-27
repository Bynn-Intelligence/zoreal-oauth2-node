import { describe, expect, it } from 'vitest';
import { Login, UserinfoError, ZorealOAuth2Client } from '../src';
import type { IdTokenClaims } from '../src';
import { CLIENT_ID, ISSUER, baseClaims, json, stubFetch, type FetchStub } from './helpers';

function loginWith(fetch: FetchStub, accessToken?: string, claims: Record<string, unknown> = {}) {
  const client = new ZorealOAuth2Client({ clientId: CLIENT_ID, issuer: ISSUER, fetch });
  return new Login({
    client,
    claims: baseClaims(claims) as unknown as IdTokenClaims,
    idToken: 'x',
    accessToken,
    scope: 'openid',
  });
}

describe('Login', () => {
  it('reads the conveniences straight from the claims', () => {
    const fetch = stubFetch(() => json({}));
    const login = loginWith(fetch, undefined, {
      age_over_18: true,
      nationality: 'SWE',
      amr: ['hwk', 'face', 'user'],
      zoreal: { trust_tier: 'high', verified_on: '2026-07' },
    });

    expect(login.sub).toBe('7QK3-9F2M-XR84-B5NP');
    expect(login.acr).toBe('zoreal.device');
    expect(login.amr).toEqual(['hwk', 'face', 'user']);
    expect(login.ageOver(18)).toBe(true);
    expect(login.ageOver(65)).toBeUndefined();
    expect(login.nationality).toBe('SWE');
    expect(login.assurance?.trust_tier).toBe('high');
  });

  it('reads the assurance ordering through live and satisfiesAcr', () => {
    const fetch = stubFetch(() => json({}));

    const live = loginWith(fetch, undefined, { acr: 'zoreal.live' });
    expect(live.live).toBe(true);
    expect(live.satisfiesAcr('zoreal.device')).toBe(true);
    // Unknown values satisfy nothing: a predicate answers, it never throws.
    expect(live.satisfiesAcr('made.up')).toBe(false);

    const device = loginWith(fetch, undefined, { acr: 'zoreal.device' });
    expect(device.live).toBe(false);
    expect(device.satisfiesAcr('zoreal.live')).toBe(false);
  });

  it('resolves userinfo to an empty object when there is no access token, never fetching', async () => {
    const fetch = stubFetch(() => json({}));
    const login = loginWith(fetch, undefined);

    await expect(login.userinfo()).resolves.toEqual({});
    await expect(login.email()).resolves.toBeUndefined();
    await expect(login.emailVerified()).resolves.toBe(false);
    expect(fetch.calls).toHaveLength(0);
  });

  it('fetches userinfo once and memoizes it across the accessors', async () => {
    const fetch = stubFetch(() =>
      json({
        email: 'holder@example.com',
        email_verified: true,
        name: 'ANNA LINDQVIST',
        given_name: 'ANNA',
        family_name: 'LINDQVIST',
        birthdate: '1994-03-12',
        document_type: 'P',
        document_number: 'X1234567',
        issuing_country: 'SWE',
        document_expires_on: '2031-03-11',
      })
    );
    const login = loginWith(fetch, 'zat_test');

    const [email, name, birthdate] = await Promise.all([
      login.email(),
      login.name(),
      login.birthdate(),
    ]);
    expect(email).toBe('holder@example.com');
    expect(name).toBe('ANNA LINDQVIST');
    expect(birthdate).toBe('1994-03-12');
    await expect(login.emailVerified()).resolves.toBe(true);
    await expect(login.givenName()).resolves.toBe('ANNA');
    await expect(login.familyName()).resolves.toBe('LINDQVIST');
    await expect(login.documentType()).resolves.toBe('P');
    await expect(login.documentNumber()).resolves.toBe('X1234567');
    await expect(login.issuingCountry()).resolves.toBe('SWE');
    await expect(login.documentExpiresOn()).resolves.toBe('2031-03-11');
    // Registrable, not served yet: resolves undefined rather than throwing.
    await expect(login.portrait()).resolves.toBeUndefined();

    expect(fetch.callsTo('/userinfo')).toHaveLength(1);
  });

  it('does not memoize a failed userinfo fetch: the next call tries again', async () => {
    let healthy = false;
    const fetch = stubFetch(() =>
      healthy
        ? json({ email: 'holder@example.com' })
        : json({ error: 'invalid_token', error_description: 'the access token is not valid' }, 401)
    );
    const login = loginWith(fetch, 'zat_test');

    await expect(login.email()).rejects.toBeInstanceOf(UserinfoError);
    healthy = true;
    await expect(login.email()).resolves.toBe('holder@example.com');
    expect(fetch.callsTo('/userinfo')).toHaveLength(2);
  });
});
