# @zoreal/oauth2-node

[![npm](https://img.shields.io/npm/v/@zoreal/oauth2-node)](https://www.npmjs.com/package/@zoreal/oauth2-node) [![types](https://img.shields.io/npm/types/@zoreal/oauth2-node)](https://www.npmjs.com/package/@zoreal/oauth2-node) [![CI](https://img.shields.io/github/actions/workflow/status/Bynn-Intelligence/zoreal-oauth2-node/ci.yml?branch=main&label=CI)](https://github.com/Bynn-Intelligence/zoreal-oauth2-node/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Bynn-Intelligence/zoreal-oauth2-node/badge)](https://scorecard.dev/viewer/?uri=github.com/Bynn-Intelligence/zoreal-oauth2-node) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Login with ZOREAL for Node.js backends: the relying-party half of the flow that
[`@zoreal/oauth2-react`](https://github.com/Bynn-Intelligence/zoreal-oauth2-react)
starts in the browser.

The browser SDK runs the pairing (QR or app link), and hands your frontend an
authorization `code` plus the `code_verifier` and `nonce` it generated. Your
frontend posts all three to your backend, and this package does the rest: the
code exchange with your client authentication, ES256 verification of the ID
token against the provider's JWKS, and the `/userinfo` read for personal
claims.

```
@zoreal/oauth2-node (this package)   your backend: exchange, verify, userinfo
@zoreal/oauth2-react                 your frontend: the button, the QR, the polling
```

## Install

```sh
npm install @zoreal/oauth2-node
```

Node.js >= 18 (the built-in `fetch` is the transport). One dependency:
[`jose`](https://github.com/panva/jose). ESM and CommonJS builds ship, with
types.

## Getting your credentials

Everything the client constructor needs comes from a ZOREAL **asset**.

1. Create an account at **https://zoreal.com** and open **Assets**.
2. **Create an asset** — a *website* (a domain you own) or an *app bundle* (a
   reverse-DNS bundle id). An asset is the thing users log in to; its token is
   your `clientId` and it looks like `ast_...`.
3. On the asset, open the **OAuth2** tab and set:
   - the **redirect URIs** and **JavaScript origins** your app uses (requests
     from anything not registered are rejected — this is the core control),
   - the **scopes** the client is allowed to request (see the catalogue below),
   - your **client authentication**: generate a **client secret**
     (`client_secret_basic`), or register a **JWKS** for `private_key_jwt`. A
     public client authenticates with PKCE alone and no secret.
4. A website asset must **verify its domain** (a DNS or meta-tag proof, shown in
   the dashboard) before it can request personal-data scopes or sign users in;
   the verified domain is what your users' `sub` is pairwise against.

The `clientId` is public — it ships in your frontend. The client secret is not:
keep it in your server's secret store (an environment variable, a secrets
manager), never in the browser.

### There is no test-identity sandbox — and that is deliberate

ZOREAL **never issues fake or sandbox humans**: a pool of test identities would
be a fraud vector against the exact thing the product proves. So you always
authenticate **real** ZOREAL IDs.

To develop and test, **create a free ZOREAL ID for yourself** (enrol in the
ZOREAL ID app) and sign in with it. Mark your asset's environment **sandbox**
in the dashboard while building — a sandbox asset may register
`http://localhost` origins and redirect URIs that a production asset may not —
and flip it to production when you ship. The identities are real either way;
only the allowed origins differ.

## Quick start

Build one client at boot and share it; it is safe to use concurrently.

```ts
import { ZorealOAuth2Client } from '@zoreal/oauth2-node';

export const zoreal = new ZorealOAuth2Client({
  clientId: process.env.ZOREAL_CLIENT_ID!,                       // ast_...
  issuer: process.env.ZOREAL_ISSUER ?? 'https://id.zoreal.com',
  auth: {
    method: 'client_secret_basic',
    clientSecret: process.env.ZOREAL_CLIENT_SECRET!,
  },
});
```

The endpoint your frontend posts to (Express here; any framework works the
same way):

```ts
app.post('/api/auth/zoreal', async (req, res) => {
  const { code, code_verifier, nonce } = req.body;
  const login = await zoreal.authenticate(code, code_verifier, nonce);

  login.sub;                   // "TC5X-JN7G-YTSE-6E63" — pairwise, stable for YOUR domain
  login.acr;                   // "zoreal.live" | "zoreal.device" | "zoreal.session"
  login.assurance;             // uniqueness basis, verification month, chip liveness, trust tier
  await login.email();         // from /userinfo, when your client has the email scope
  await login.emailVerified();
  await login.name();          // from /userinfo, profile.name scope
});
```

Account matching, the shape that works:

```ts
let user = await users.findBy({ provider: 'zoreal', uid: login.sub });
if (!user) {
  if (await login.emailVerified()) {
    user = await users.findBy({ email: await login.email() }); // claim, don't collide
  }
  user ??= await users.create({ email: await login.email() });
  await users.update(user, { provider: 'zoreal', uid: login.sub });
}
```

## Assurance levels — `acr`, and requiring a liveness check

### What `acr` is

`acr` is an OpenID Connect standard claim — *Authentication Context Class
Reference*. It is a single string in the ID token that says **how strongly this
particular login was authenticated**. Every ZOREAL login carries one, and it is
the difference between "someone who once enrolled this identity is behind this
request" and "a live human, verified to be the right one, is behind this request
right now".

It answers a question the `sub` cannot. `sub` tells you *who* (a stable, pairwise
identifier for this person at your site). `acr` tells you *how sure ZOREAL is that
the person is really there for this login*. A stolen, unlocked phone can still
produce a `sub`; it cannot produce a fresh `zoreal.live`.

### The three levels

Ordered weakest to strongest. Each is what actually happened, never what was
requested — a login that could only reach a weaker level says so honestly rather
than claiming the level you asked for.

| `acr` | What the holder did | `amr` | What it proves | What it does **not** prove |
|---|---|---|---|---|
| `zoreal.session` | Nothing — a returning holder at a site they have used before, resumed silently from an existing ZOREAL session, no phone interaction | `[]` | Continuity: the same browser/session ZOREAL already knew | That the holder is present, or even awake |
| `zoreal.device` | Approved the login on their enrolled phone: a signature from a key in the phone's secure element, released by a local biometric or passcode unlock | `["hwk","user"]` | Possession of the enrolled device **and** a local unlock on it | That a live face was captured for *this* login — an unlocked phone in the wrong hands still signs |
| `zoreal.live` | All of the above **plus** a fresh face capture this login: a flash-plus-zoom video scored for presentation attacks and screen replay (moire), matched 1:1 against the government document read at enrolment | `["hwk","face","user"]` | A live, real, unique human, verified to be the enrolled person, **at the moment of this login** | — (this is the strongest level) |

`amr` (*Authentication Methods References*) is the companion claim listing the
factors used: `hwk` a hardware key, `user` a user-presence/unlock gesture, `face`
a face biometric. `zoreal.live` is exactly `zoreal.device` with `face` added,
because a live login is a device approval with a capture on top. The package
exports the same ordering as the frozen `ACR_ORDER` constant, if you want the
ranks directly.

The **default is `zoreal.device`**, never `zoreal.session`: a login that asks for
nothing still requires the enrolled phone and a local unlock. Silence has to be
explicitly asked for (`prompt=none`), and it succeeds only for a returning holder
at a site whose consent they have already given.

### When to require which

- **`zoreal.session`** — you never *require* this; it is what a returning holder
  gets for a low-stakes convenience re-auth when they ask for the silent path.
- **`zoreal.device`** (the default) — a forum, a community, a normal account
  login. Possession of the enrolled phone plus a local unlock is a high bar
  already; most sites want exactly this and should pass no `acr` at all.
- **`zoreal.live`** — a bank onboarding, a high-value transaction, an age-gated
  purchase, a first login, a "confirm it is really you" step before a sensitive
  action. Anywhere a *fresh, unforgeable proof of the live, right human* is worth
  the few seconds a face capture costs.

### Requesting versus verifying — the one rule that matters

Requesting a level and verifying it are **two separate steps, and only the second
is security**:

1. **Request** it on the wire, in the frontend, with the SDK's
   `acr_values: 'zoreal.live'`. This is what makes the holder's ZOREAL ID app run
   the face capture before it will approve. It is **advisory** — it shapes what
   the holder is asked to do, nothing more. A browser is attacker-controlled; a
   value that only travels through it proves nothing.
2. **Verify** it here, at token exchange, by passing `acr` on the verification
   options. The signed `acr` claim in the ID token — minted by ZOREAL, not by the
   browser — is the proof.

```ts
const login = await zoreal.authenticate(code, code_verifier, {
  nonce,
  acr: 'zoreal.live', // rejects with VerificationError unless the signed token says so
});

login.acr;                           // "zoreal.live" — what actually happened
login.live;                          // convenience: acr === 'zoreal.live'
login.satisfiesAcr('zoreal.device'); // true (live is stronger than device)
```

**An RP that requests `zoreal.live` on the wire but never passes `acr` here has
checked nothing** — it has only asked the holder nicely and then trusted a value
it never validated.

### How the check behaves

Verification satisfies **upward**: `zoreal.session < zoreal.device <
zoreal.live`, so a requirement of `zoreal.device` accepts a `zoreal.live` token
(the holder gave you *more* assurance than you demanded). A token whose `acr` is
below the requirement, missing entirely, or outside the vocabulary is refused
with `VerificationError`. An unknown *required* value — a typo like
`'zoreal.liveness'` — throws `ConfigurationError` instead, because that is a bug
in your code, not a bad token, and failing every login silently is worse than
saying so.

If you prefer to branch rather than throw, omit `acr` and inspect the result
with the `satisfiesAcr` predicate:

```ts
const login = await zoreal.authenticate(code, code_verifier, nonce);
if (!login.satisfiesAcr('zoreal.live')) {
  // step the user up, or refuse the sensitive action
}
```

`satisfiesAcr` runs the same ordering as the floor check and returns `false` for
anything it cannot rank, so it never throws: the predicate is the branch-yourself
path, and the `acr` option is the enforce-for-me path.

### `acr` versus the assurance block

Do not confuse `acr` with `login.assurance`. `acr` grades *this login event*.
The **assurance block** (`login.assurance`, the `zoreal` claim) describes the
*identity behind it* — how the person was verified at enrolment: the `uniqueness`
basis, the `verified_on` month, whether chip liveness was proven
(`chip_liveness_proven`), the `trust_tier`, and the device's `key_protection`.
One is about now; the other is about who they are. A high-value flow usually
wants both: `acr: 'zoreal.live'` for presence, and the assurance block for the
strength of the underlying identity proofing. Its full schema is in
[The assurance block](#the-assurance-block) below.

## Client authentication

Four registrable methods; `auth` takes exactly one of them.

```ts
// Public client (the default): no secret, no key. PKCE is the only proof,
// and Tier A scopes are all such a client can have been granted.
auth: { method: 'none' }

// Confidential: the secret travels as HTTP Basic, never as a form field.
auth: { method: 'client_secret_basic', clientSecret: '...' }

// Confidential: the package builds and signs a fresh RFC 7523 assertion per
// exchange. PEM string (PKCS8 or SEC1/PKCS1), node KeyObject, or CryptoKey.
auth: { method: 'private_key_jwt', privateKey: pem, kid: 'key-2026' }

// Mutual TLS at the transport. Read the note below before picking this.
auth: { method: 'tls_client_auth', cert, key }
```

**`private_key_jwt`** signs `iss` = `sub` = your client_id, `aud` =
`{issuer}/token`, `exp` 60 seconds out (the provider's maximum), and a fresh
`jti` per assertion, because the provider accepts each one exactly once. A
P-256 key signs ES256, which is the preferred pairing and the one that matches
the provider's certified-key path; an RSA key signs RS256. Other curves are
refused at configuration time rather than at the provider.

**`tls_client_auth`** is registrable, but the provider currently answers
`501` — `not implemented at this endpoint yet` — and this package surfaces
that as the `ExchangeError` it is rather than faking the method. The
certificate and key are applied through [undici](https://github.com/nodejs/undici)'s
`Agent`, so `undici` is an optional peer dependency you install only for this
method: `npm install undici`. The other three methods never load it.

## What each call does

| Call | What happens |
|---|---|
| `authenticate(code, codeVerifier, options?)` | `exchange` + `verifyIdToken`, returns a `Login` |
| `exchange(code, codeVerifier)` | `POST {issuer}/token` with your client authentication |
| `verifyIdToken(jwt, options?)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, plus `nonce` and the `acr` floor when given |
| `userinfo(accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `login.userinfo()` | the above, once, memoized; `{}` when there is no access token |

`options` is the nonce string alone — the common case, as in the quick start —
or `{ nonce?, acr? }`.

`Login` also carries `sub`, `acr`, `live`, `satisfiesAcr(required)`, `amr`,
`assurance`, `ageOver(threshold)`,
`nationality`, `claims`, `idToken`, `accessToken` and `scope`, plus async
accessors for every `/userinfo` claim: `email()`, `emailVerified()`, `name()`,
`givenName()`, `familyName()`, `birthdate()`, `documentType()`,
`documentNumber()`, `issuingCountry()`, `documentExpiresOn()`, `portrait()`.

## Scopes and claims

Scopes are requested in the **frontend** (the SDK's `scope` string, always
starting with `openid`), consented to by the holder, and pre-authorized on your
asset. What each grants and where it is delivered:

| Scope | Claims | Delivered in | Tier | Requires |
|---|---|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`, and the assurance block | ID token | A | any client |
| `zoreal.age` | `age_over_13/16/18/21/65` booleans — only the thresholds you registered, never an age or birthdate | ID token | A | any client |
| `zoreal.nationality` | `nationality` (ISO 3166-1 alpha-3) | ID token | A | any client |
| `email` | `email`, `email_verified` | `/userinfo` | B | confidential client + verified domain |
| `profile.name` | `name`, `given_name`, `family_name` | `/userinfo` | B | confidential client + verified domain |
| `profile.birthdate` | `birthdate` (full ISO 8601 date) | `/userinfo` | B | confidential client + verified domain |
| `profile.document` | `document_type`, `document_number`, `issuing_country`, `document_expires_on` | `/userinfo` | B | confidential client + verified domain |
| `profile.portrait` | `portrait` (the chip's facial image; GDPR Article 9 data) | `/userinfo` | C | confidential client + verified domain — *registrable but not served yet* |

- **Tier A** rides in the ID token and is available to every client, so the
  no-backend browser button can use it. Read it straight off the `Login`:
  `login.sub`, `login.acr`, `login.amr`, `login.assurance`,
  `login.ageOver(18)`, `login.nationality`.
- **Tier B and C** are personal data, served only from `/userinfo` to a
  confidential client on a domain you have verified, and never placed in a
  browser token. They arrive through the async accessors — `await
  login.email()`, `await login.name()`, and the rest — each of which reads
  `/userinfo` once and memoizes it.
- **Age thresholds are a fixed set** — 13, 16, 18, 21, 65 — that you register on
  the asset. `login.ageOver(n)` returns `undefined` for a threshold you did not
  register (no claim was minted), which is different from `false`.

## Error reference

`exchange` / `authenticate` reject with `ExchangeError`, which carries the
provider's own `oauthError` code and `description` verbatim (and the HTTP
`status` when there was a response). What you will actually see:

| `oauthError` | Cause | Retryable? |
|---|---|---|
| `invalid_grant` | The code is spent — unknown, expired (60s), already used, PKCE mismatch, or the asset's domain verification lapsed mid-flow | No. Start a **new** login; the code cannot be reused |
| `invalid_request` | Client authentication failed — wrong secret, a bad `private_key_jwt` assertion, or `tls_client_auth` (not accepted at `/token` yet) | No. Fix your client configuration |
| `unsupported_grant_type` | Something other than `authorization_code` reached `/token` | No. A bug |

Errors that surface in the **frontend** instead, before your backend is
involved (from the SDK's `onError` / `onNonOAuthError`), so handle them there:

| Where | Code | Meaning |
|---|---|---|
| `/pair` | `invalid_scope` | A scope not on the asset's allowed list, or a Tier B scope from a public client |
| `/pair` | `invalid_request` | Missing PKCE/nonce, an unverified sector, an unregistered `redirect_uri`, or an unknown `acr_values` |
| `/pair` | `login_required` | `prompt=none` with no silent session to resume — the expected quiet outcome, not a failure |
| pairing | `request_denied` | The holder declined in their ZOREAL ID app — **not an error to alarm on**; offer to try again |
| pairing | `request_expired` | The pairing window elapsed, or a required liveness the device could not meet — offer to try again |

`request_denied` is a person choosing not to log in, not a fault: treat it as a
cancel — keep the button where it is and let them try again. It never reaches
your backend, so there is nothing to catch here for it.

This package's own classes, all extending `ZorealOAuth2Error`:

| Class | Thrown when | Extra fields |
|---|---|---|
| `ConfigurationError` | You built the client wrong, or asked to verify an `acr` outside the vocabulary — a bug in your code, not a bad token | — |
| `ExchangeError` | The provider refused the code exchange | `oauthError`, `description`, `status?` |
| `VerificationError` | The ID token did not verify: signature, `iss`, `aud`, `exp`, `nonce`, or the `acr` floor | — |
| `UserinfoError` | The `/userinfo` read failed | `status?` |

A returning user matched on `sub` can survive a caught `UserinfoError`; a signup
that needs the email cannot. No token value ever appears in an error message.

## The assurance block

`login.assurance` is the ID token's `zoreal` claim (typed `ZorealAssurance`) — a
description of the strength of the *identity* behind this login, distinct from
`acr`, which grades the *login event*. Its keys and their value sets:

| Key | Values | Meaning |
|---|---|---|
| `uniqueness` | `personal_number` \| `document` \| `none` | The anchor the holder is deduplicated on. `personal_number` (a national number from the chip) is strongest; `none` means no reliable anchor |
| `verified_on` | `"YYYY-MM"` | The month the underlying document was verified. Quantised to a month on purpose — a day-precision date is a cross-site correlator |
| `chip_liveness_proven` | `true` \| `false` | Whether the passport chip's active-authentication challenge was proven (a genuine chip, not a clone) |
| `trust_tier` | `high` \| `standard` | `high` when `chip_liveness_proven`, else `standard` |
| `key_protection` | `secure_enclave` \| `strongbox` \| `tee` \| `software` | How the holder's device key is protected. `software` means no hardware attestation |

`acr` grades the login event; the assurance block grades the identity. A
high-value flow usually pairs the two — `acr: 'zoreal.live'` for fresh presence,
and an assurance-block check for identity strength:

```ts
const login = await zoreal.authenticate(code, code_verifier, {
  nonce,
  acr: 'zoreal.live',
});

const { uniqueness, trust_tier } = login.assurance ?? {};
if (uniqueness !== 'personal_number' || trust_tier !== 'high') {
  // strong enough to sign in, not strong enough for THIS action: step up or refuse
}
```

## A complete example

An Express handler, end to end — the shape a real integration takes.

```ts
import { ExchangeError, VerificationError, UserinfoError } from '@zoreal/oauth2-node';
import { zoreal } from './zoreal'; // the client built once at boot, from Quick start

// Your frontend's <ZorealLogin onSuccess> posts { code, code_verifier, nonce }
// here over your own TLS. Protect THIS route with your framework's normal CSRF /
// same-origin defence, exactly as you would any login endpoint — the ZOREAL
// nonce protects the token, not your route.
app.post('/api/auth/zoreal', async (req, res) => {
  const { code, code_verifier, nonce } = req.body;

  try {
    const login = await zoreal.authenticate(code, code_verifier, nonce);
    // pass { nonce, acr: 'zoreal.live' } instead for a step-up / high-value login

    let user = await users.findBy({ provider: 'zoreal', uid: login.sub });
    if (!user) {
      // A subject we have not seen. A signup needs personal data, so a
      // UserinfoError here is fatal — the returning path above never reaches it.
      const email = (await login.emailVerified()) ? await login.email() : undefined;
      // Claim an existing account that owns this verified email rather than
      // colliding on the unique index; otherwise create one.
      if (email) user = await users.findBy({ email });
      user ??= await users.create({ email, fullName: await login.name() });
      await users.update(user, { provider: 'zoreal', uid: login.sub });
    }

    // Session-fixation defence: a fresh session id on privilege change.
    await new Promise<void>((resolve, reject) =>
      req.session.regenerate((err: unknown) => (err ? reject(err) : resolve())),
    );
    req.session.userId = user.id;
    res.json({ ok: true });
  } catch (error) {
    if (error instanceof ExchangeError || error instanceof VerificationError) {
      // A spent code or a token that did not verify: the login must be restarted.
      return res.status(401).json({ error: 'sign_in_failed' });
    }
    if (error instanceof UserinfoError) {
      // Personal data was unreachable. Fine for a returning user matched on sub;
      // fatal for a signup that needs the email, as here.
      return res.status(401).json({ error: 'sign_in_failed' });
    }
    throw error; // an unexpected error is not a failed login; let it surface
  }
});
```

## Things worth knowing before you integrate

- **The ID token never carries personal data.** `sub`, timing, `acr`/`amr`,
  the assurance block, and — if registered — `age_over_*` booleans and
  `nationality`. Email, names, birthdate and document fields come only from
  `/userinfo`, which is why `authenticate` alone is not enough for a signup.
- **The access token lives 10 minutes.** Read `/userinfo` while handling the
  login; do not store the token for later.
- **`sub` is pairwise per verified domain.** It is the right account key and
  it is derived from your registered sector: changing your asset's domain
  rotates every `sub` you have stored. Plan domain changes as a migration.
- **ES256 only.** The provider signs ID tokens with nothing else, and this
  package refuses other algorithms rather than negotiating.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **`profile.portrait` is registrable but not served yet.** The `portrait()`
  accessor exists so the integration is written once; it resolves `undefined`
  until the provider ships the claim.

## Security

- **Always pass the nonce through, and protect your own endpoint too.** The SDK
  generates the nonce and hands it to your frontend in `onSuccess`; passing it
  to `authenticate` lets this package confirm the ID token was minted for *this*
  login rather than substituted. Two things the nonce does **not** do: it is not
  your endpoint's CSRF token — protect your `/api/auth/zoreal` route with your
  framework's normal CSRF / same-origin defence — and PKCE, not the nonce, is
  what proves whoever exchanges the code is whoever started the flow.
- **PKCE is mandatory and already handled.** The browser SDK generates the
  verifier and challenge; your frontend forwards the `code_verifier`, and
  `exchange` presents it. There is no plain, non-PKCE path to fall back to.
- **The `issuer` must match the token's `iss` exactly.** It is compared as a
  string, not normalized. Production is `https://id.zoreal.com`; set `issuer`
  to anything else only when you were handed a non-production provider URL to
  point at, and make it match that provider's `iss` character for character.

## Verifying this release

Every version is published from GitHub Actions with [npm provenance](https://docs.npmjs.com/generating-provenance-statements): the package page on npmjs.com carries a **Provenance** panel linking the exact commit and workflow run that built the tarball, signed through [Sigstore](https://www.sigstore.dev/) and recorded in its public transparency log. No long-lived npm token stands behind it — the workflow authenticates by OIDC ([trusted publishing](https://docs.npmjs.com/trusted-publishers)), so a leaked CI secret cannot cut a release.

Check the signatures on what you actually installed:

```sh
npm install @zoreal/oauth2-node
npm audit signatures
```

## The ZOREAL OAuth2 library family

| Repository | Package | Role |
|---|---|---|
| zoreal-oauth2-react | @zoreal/oauth2-react (npm) | React frontend: the button, the QR, the polling |
| zoreal-oauth2-js | @zoreal/oauth2-js (npm) | Framework-free browser core |
| zoreal-oauth2-react-native | @zoreal/oauth2-react-native (npm) | React Native frontend |
| zoreal-oauth2-node | @zoreal/oauth2-node (npm) | Node.js backend |
| zoreal-oauth2-ruby | zoreal-oauth2 (RubyGems) | Ruby backend |
| zoreal-oauth2-python | zoreal-oauth2 (PyPI) | Python backend |
| zoreal-oauth2-php | zoreal/oauth2 (Packagist) | PHP backend |
| zoreal-oauth2-go | github.com/Bynn-Intelligence/zoreal-oauth2-go | Go backend |
| zoreal-oauth2-java | com.zoreal:oauth2 (Maven Central) | JVM backend |
| zoreal-oauth2-dotnet | Zoreal.OAuth2 (NuGet) | .NET backend |

## License

MIT.
