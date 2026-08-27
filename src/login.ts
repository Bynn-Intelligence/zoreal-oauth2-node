import { acrRank } from './acr';
import type { ZorealOAuth2Client } from './client';
import type { AcrValue, IdTokenClaims, RequiredAcr, UserinfoClaims, ZorealAssurance } from './types';

/**
 * One verified login. The ID token claims are already checked when this
 * exists; userinfo is fetched on first use, because the ID token never
 * carries personal data and not every login needs any.
 */
export class Login {
  /** The verified ID token claims. */
  readonly claims: IdTokenClaims;
  /** The raw compact JWT the claims came from. */
  readonly idToken: string;
  /** From the token response. The access token lives ten minutes. */
  readonly accessToken?: string;
  readonly scope?: string;

  #client: ZorealOAuth2Client;
  #userinfo?: Promise<UserinfoClaims>;

  constructor(options: {
    client: ZorealOAuth2Client;
    claims: IdTokenClaims;
    idToken: string;
    accessToken?: string;
    scope?: string;
  }) {
    this.#client = options.client;
    this.claims = options.claims;
    this.idToken = options.idToken;
    this.accessToken = options.accessToken;
    this.scope = options.scope;
  }

  /**
   * The pairwise subject: stable for your verified domain, meaningless to
   * anyone else. This is the value to key accounts on — and it is derived
   * from YOUR registered sector, so changing your asset's domain rotates
   * every sub you have stored.
   */
  get sub(): string {
    return this.claims.sub;
  }

  /**
   * How the login was authenticated: zoreal.live, zoreal.device or
   * zoreal.session. Describes what happened, never what was requested.
   */
  get acr(): AcrValue | undefined {
    return this.claims.acr;
  }

  /**
   * A fresh liveness capture backed this login. The convenience spelling of
   * acr === 'zoreal.live'; for enforcement, pass `acr` to authenticate and
   * let verification refuse the token instead of checking after.
   */
  get live(): boolean {
    return this.acr === 'zoreal.live';
  }

  /**
   * Equal or stronger satisfies, on the client's ordering
   * (zoreal.session < zoreal.device < zoreal.live). Unknown values satisfy
   * nothing.
   */
  satisfiesAcr(required: RequiredAcr): boolean {
    const actual = acrRank(this.acr);
    const wanted = acrRank(required);
    return actual !== undefined && wanted !== undefined && actual >= wanted;
  }

  get amr(): string[] | undefined {
    return this.claims.amr;
  }

  /**
   * The assurance block: uniqueness basis, verification month, chip
   * liveness, trust tier, key protection.
   */
  get assurance(): ZorealAssurance | undefined {
    return this.claims.zoreal;
  }

  /**
   * zoreal.age scope: the registered thresholds arrive as booleans
   * (age_over_18 and so on), never an age. undefined when the threshold was
   * not registered for your client.
   */
  ageOver(threshold: number): boolean | undefined {
    const value = this.claims[`age_over_${Math.trunc(threshold)}`];
    return typeof value === 'boolean' ? value : undefined;
  }

  /** zoreal.nationality scope: ISO 3166-1 alpha-3, read from the document chip. */
  get nationality(): string | undefined {
    return this.claims.nationality;
  }

  /**
   * The Tier B claims, from /userinfo, fetched once and memoized. Rejects
   * with UserinfoError when the endpoint refuses — catch it if your flow can
   * continue without personal data, as a returning user matched on sub can;
   * a failed fetch is not memoized, so the next call tries again. Resolves
   * to an empty object when the exchange carried no access token.
   */
  userinfo(): Promise<UserinfoClaims> {
    this.#userinfo ??= this.accessToken
      ? this.#client.userinfo(this.accessToken).catch((error: unknown) => {
          this.#userinfo = undefined;
          throw error;
        })
      : Promise.resolve({});
    return this.#userinfo;
  }

  /** email scope. The address the holder verified with ZOREAL. */
  async email(): Promise<string | undefined> {
    return (await this.userinfo()).email;
  }

  async emailVerified(): Promise<boolean> {
    return (await this.userinfo()).email_verified === true;
  }

  /** profile.name scope. */
  async name(): Promise<string | undefined> {
    return (await this.userinfo()).name;
  }

  async givenName(): Promise<string | undefined> {
    return (await this.userinfo()).given_name;
  }

  async familyName(): Promise<string | undefined> {
    return (await this.userinfo()).family_name;
  }

  /** ISO 8601 full date, from the profile.birthdate scope. */
  async birthdate(): Promise<string | undefined> {
    return (await this.userinfo()).birthdate;
  }

  /** profile.document scope. */
  async documentType(): Promise<string | undefined> {
    return (await this.userinfo()).document_type;
  }

  async documentNumber(): Promise<string | undefined> {
    return (await this.userinfo()).document_number;
  }

  async issuingCountry(): Promise<string | undefined> {
    return (await this.userinfo()).issuing_country;
  }

  async documentExpiresOn(): Promise<string | undefined> {
    return (await this.userinfo()).document_expires_on;
  }

  /**
   * profile.portrait scope. Registrable, but the provider does not serve the
   * claim yet, so this resolves undefined today; the accessor exists so the
   * integration is written once.
   */
  async portrait(): Promise<string | undefined> {
    return (await this.userinfo()).portrait;
  }
}
