# ratify-verifier-oidc-metadata

A [Ratify](https://github.com/notaryproject/ratify) v2 verifier that checks
an OIDC ID token carried as signed metadata inside a
[Notary Project](https://notaryproject.dev) signature.

A signer asks its OIDC provider for an ID token whose audience is bound to one
image digest, then stores that token in the signature. The verifier accepts
the signature only if the token was issued by a trusted issuer for that exact
image, and it returns the token's claims so that an admission policy can
decide on them.

The verifier makes no policy decisions. It reports who issued the token and
what the token says. Your policy decides whether those claims are acceptable.

## What the verifier checks

For each signature of an artifact, in order:

1. **Notary signature.** The signature is verified by
   [notation-go](https://github.com/notaryproject/notation-go) against the
   configured certificates (`ca`, `tsa` or `signingAuthority` trust stores)
   and trusted identities. An optional verification plugin
   (`pluginDirectory` / `pluginConfig`) is supported for signatures that need
   one, such as those made with AWS Signer.
2. **Token present.** The signed metadata key (`metadataKey`, default
   `ci.id-token`) holds a JWT.
3. **Issuer trusted.** The token's `iss` claim is on the configured `issuers`
   list. Any other issuer is refused.
4. **Signature valid.** The token is an RS256 JWT signed by a key the issuer
   published. Keys come from `jwksFiles`, from `jwksURL`, or from both.
   Symmetric and `none` algorithms are refused.
5. **Audience bound to the image.** `aud` is exactly one value:
   `audiencePrefix` followed by the image digest (default prefix
   `oci-sign:`). A token issued for another image or another audience is
   refused.
6. **Token valid when the signature was made.** The Notary signing time lies
   between the token's `iat` and `exp`, with a 5 minute allowance for clock
   differences. The token's expiry is not compared with the current time, so
   an image signed while its token was valid stays verifiable later.

A signature that passes returns:

```json
{
  "issuer": "https://oidc.example.com",
  "claims": { "...": "all claims of the token" },
  "signingTime": "2026-11-19T09:00:00Z",
  "signerSubject": "CN=...",
  "signedAttributes": { "...": "string extended attributes of the signature" }
}
```

The raw token is never returned.

## Configuration

```yaml
type: oidc-metadata
name: oidc-metadata-1
parameters:
  scopes: ["registry.example.com/*"]        # notation trust policy scopes
  trustedIdentities: ["*"]                  # notation trust policy identities
  certificates:                             # notation trust stores
    - type: ca                              # ca | tsa | signingAuthority
      inline:
        certs: |
          -----BEGIN CERTIFICATE-----
          ...
          -----END CERTIFICATE-----
  # Optional: Notation verification plugins, e.g. the AWS Signer plugin.
  pluginDirectory: /plugins                 # {dir}/{name}/notation-{name}
  pluginConfig:
    aws-region: us-east-1
  # Optional: where the token is stored and what audience it must have.
  metadataKey: ci.id-token                  # default
  audiencePrefix: oci-sign:                 # default
  issuers:
    - issuer: https://token.actions.githubusercontent.com
      jwksURL: https://token.actions.githubusercontent.com/.well-known/jwks
      jwksFiles: [/etc/ratify/issuer-keys/github-actions.jwks.json]
    - issuer: https://oidc.example.com
      jwksURL: https://oidc.example.com/.well-known/jwks
      jwksFiles: [/etc/ratify/issuer-keys/example.jwks.json]
```

Parameter notes:

- `issuers` is required. Each issuer needs `jwksURL`, `jwksFiles`, or both.
- `jwksURL` must be `https`.
- `jwksFiles` are key sets kept on disk. Keep retired keys in them so that
  images signed under those keys still verify. A file that is missing or has a
  weak key stops the verifier from starting.
- Keys must be RSA with at least 2048 bits.

### Key rotation

- A key id never changes its key. The first key seen for an id is kept.
- A key id that is not known triggers at most one fetch of `jwksURL` per issuer
  per minute. Unknown key ids cannot be used to flood the issuer.
- When a key id is unknown, the `jwksFiles` are re-read before `jwksURL` is
  fetched, so keys added to the files are picked up without a restart.

## Using it with your own OIDC provider

The issuer must be able to:

1. **Issue an ID token with a caller-chosen audience.** The signer requests a
   token with `audience=<audiencePrefix><image digest>`. An issuer that only
   offers fixed audiences cannot bind a token to an image.
2. **Publish its signing keys as a JWKS** over HTTPS, and sign with RS256.

Then:

1. Add the issuer to `issuers` with its JWKS location.
2. In the signing step, request a token for the image digest and attach it:

   ```bash
   notation sign --plugin <plugin> --id <key id> \
     --user-metadata ci.issuer="$issuer" \
     --user-metadata ci.id-token="$token" \
     "$image@$digest"
   ```

   `ci.issuer` is for people reading the signature. The verifier does not use
   it: it reads the issuer from the token.
3. Write admission rules for that issuer's claims. Claim names differ between
   providers, so do not reuse GitHub's claim names for another issuer.

The default metadata key `ci.id-token` and the `ci.issuer` annotation are
conventions, not requirements. Set `metadataKey` to change the first.

## Registering the verifier with Ratify

Ratify v2 currently registers verifiers through an internal package, so this
module cannot register itself yet. Until Ratify provides a public registration
API ([discussion #3132](https://github.com/notaryproject/ratify/discussions/3132)),
a build needs a small adapter inside Ratify's source tree:

```go
package oidcmetadatareg

import (
	oidcmetadata "github.com/shivanshs9/ratify-verifier-oidc-metadata"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/verifier"
)

func init() {
	verifier.Register(oidcmetadata.Type, func(opts verifier.NewOptions, _ []string) (ratify.Verifier, error) {
		return oidcmetadata.New(opts.Name, opts.Parameters)
	})
}
```

Once a public API exists, the module can register itself with a blank import
(`import _ "github.com/shivanshs9/ratify-verifier-oidc-metadata"`) and the
adapter can be deleted.

## Testing

```bash
go test ./...
```

The tests run an in-process OIDC issuer (an `httptest` TLS server that serves
a JWKS) and sign with test certificates from `notation-core-go`. They cover
accepted tokens, refused tokens (wrong audience, other issuer, forged
signature, symmetric and `none` algorithms, expired at signing time, missing
expiry), key rotation, and configuration errors.

## Security notes

- Trust comes from three things: the Notary certificates, the issuer list, and
  the issuer's published keys. Anyone who can write the issuer list or the key
  files controls which tokens are accepted. Protect them like code.
- The audience binding stops a token issued for one image from being moved to
  another image. It does not stop a token from being copied onto another
  signature for the same digest.
- The token is only as strong as the issuer's controls over who may request a
  token for which audience. Check that before you trust a new issuer.
- The verifier does not check revocation of individual tokens. Revocation is
  handled by short token lifetimes and by the issuer.

## Limits

- Only RS256 is supported.
- Plugin support follows `notation-go`. Plugin binaries must be present where
  `pluginDirectory` points.
- Token size adds to the signature. Check the size limits of your signing
  service.

## License

TBD.
