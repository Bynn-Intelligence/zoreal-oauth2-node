/**
 * The error taxonomy. Four failure classes, one base, and one rule that holds
 * across all of them: no token value ever appears in an error message.
 */

export class ZorealOAuth2Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The client was built without something it cannot work without. */
export class ConfigurationError extends ZorealOAuth2Error {}

/**
 * The provider refused the code exchange. `oauthError` is the RFC 6749 error
 * code and `description` the provider's own reason, verbatim: the provider's
 * words are the only signal that says WHY (a consumed code, a PKCE mismatch, a
 * lapsed sector), and rewriting them hides it.
 */
export class ExchangeError extends ZorealOAuth2Error {
  /** The RFC 6749 error code, e.g. "invalid_grant". */
  readonly oauthError: string;
  /** The provider's own reason, verbatim. */
  readonly description: string;
  /** The HTTP status of the token response, when one was received. */
  readonly status?: number;

  constructor(oauthError: string, description: string, status?: number) {
    super(`${oauthError}: ${description}`);
    this.oauthError = oauthError;
    this.description = description;
    this.status = status;
  }
}

/**
 * The ID token did not verify: bad signature, wrong issuer or audience,
 * expired, or a nonce that was not the one this login started with.
 */
export class VerificationError extends ZorealOAuth2Error {}

/**
 * /userinfo answered with anything but the claims. Callers that can live
 * without personal data (a returning user matched by sub) may catch this and
 * continue; callers that need the email should not.
 */
export class UserinfoError extends ZorealOAuth2Error {
  /** The HTTP status of the userinfo response, when one was received. */
  readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}
