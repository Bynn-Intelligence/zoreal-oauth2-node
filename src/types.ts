/**
 * The claim shapes this package hands back. Every field is optional except the
 * ones the verifier itself guarantees, and an index signature keeps forward
 * compatibility: a claim the provider adds later is readable before this
 * package names it.
 */

/** How the login was actually authenticated. Describes what happened, never what was requested. */
export type AcrValue = 'zoreal.live' | 'zoreal.device' | 'zoreal.session';

/**
 * The assurance block from the `zoreal` claim: uniqueness basis, verification
 * month, chip liveness, trust tier, key protection.
 */
export interface ZorealAssurance {
  uniqueness?: string;
  /** "YYYY-MM": the month the holder's document was verified. Never a full date. */
  verified_on?: string;
  chip_liveness_proven?: boolean;
  trust_tier?: string;
  key_protection?: string;
  [claim: string]: unknown;
}

/**
 * The verified ID token claims. The ID token never carries personal data:
 * email, names, birthdate and document fields exist only at /userinfo. With
 * the zoreal.age scope, `age_over_13/16/18/21/65` booleans appear for the
 * thresholds registered for your client — only those, and never an age.
 */
export interface IdTokenClaims {
  iss: string;
  /** Pairwise per relying-party sector: stable for YOUR verified domain, meaningless to anyone else. */
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  auth_time?: number;
  acr?: AcrValue;
  amr?: string[];
  zoreal?: ZorealAssurance;
  /** zoreal.nationality scope: ISO 3166-1 alpha-3, read from the document chip. */
  nationality?: string;
  [claim: string]: unknown;
}

/** The token endpoint's success body. The access token lives ten minutes. */
export interface TokenResponse {
  id_token: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  [field: string]: unknown;
}

/**
 * /userinfo claims, by scope: openid -> sub (always); email -> email,
 * email_verified; profile.name -> name, given_name, family_name;
 * profile.birthdate -> birthdate; profile.document -> document_type,
 * document_number, issuing_country, document_expires_on; profile.portrait ->
 * portrait (registrable, but the provider does not serve the claim yet).
 */
export interface UserinfoClaims {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  /** ISO 8601 full date, from the profile.birthdate scope. */
  birthdate?: string;
  document_type?: string;
  document_number?: string;
  issuing_country?: string;
  document_expires_on?: string;
  /** Registrable, but not served by the provider yet: absent even with the scope. */
  portrait?: string;
  [claim: string]: unknown;
}
