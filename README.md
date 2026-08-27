# @zoreal/oauth2-node

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

## What each call does

| Call | What happens |
|---|---|
| `authenticate(code, codeVerifier, nonce?)` | `exchange` + `verifyIdToken`, returns a `Login` |
| `exchange(code, codeVerifier)` | `POST {issuer}/token` with your client authentication |
| `verifyIdToken(jwt, nonce?)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, and `nonce` when given |
| `userinfo(accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `login.userinfo()` | the above, once, memoized; `{}` when there is no access token |

`Login` also carries `sub`, `acr`, `amr`, `assurance`, `ageOver(threshold)`,
`nationality`, `claims`, `idToken`, `accessToken` and `scope`, plus async
accessors for every `/userinfo` claim: `email()`, `emailVerified()`, `name()`,
`givenName()`, `familyName()`, `birthdate()`, `documentType()`,
`documentNumber()`, `issuingCountry()`, `documentExpiresOn()`, `portrait()`.

Errors: `ConfigurationError`, `ExchangeError` (carries the provider's OAuth
error code, its reason verbatim, and the HTTP status), `VerificationError`,
`UserinfoError`. A returning user matched on `sub` can survive a caught
`UserinfoError`; a signup that needs the email cannot. No token value ever
appears in an error message.

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
- **Always pass the nonce through.** The SDK generates it and gives it to
  your frontend in `onSuccess`; without it your backend cannot tell a
  substituted ID token from the real one.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **Sandbox clients accept localhost origins; production clients do not.**
  Registration lives in the ZOREAL dashboard on the asset's OAuth2 tab; Tier B
  scopes (email, profile.\*) need a confidential client on a verified domain.
- **`profile.portrait` is registrable but not served yet.** The `portrait()`
  accessor exists so the integration is written once; it resolves `undefined`
  until the provider ships the claim.

## Development against a local provider

Point `issuer` at your provider instance. The issuer value must match the
`iss` inside the tokens exactly — it is compared, not normalized.

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
