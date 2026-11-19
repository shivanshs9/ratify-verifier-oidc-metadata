package oidcmetadata

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// A token is requested seconds before the signature is made. The window
	// only has to absorb clock differences between the issuer and the signer.
	signingTimeSkew = 5 * time.Minute

	// An unknown key id triggers at most one fetch of the issuer's published
	// keys per interval, so made-up key ids cannot be used to flood the issuer.
	keyFetchInterval = time.Minute
	keyFetchTimeout  = 3 * time.Second
	maxKeySetBytes   = 1 << 20
)

type issuerOptions struct {
	// Issuer is the exact "iss" value of accepted tokens. Required.
	Issuer string `json:"issuer"`

	// JWKSURL is where the issuer publishes its current keys. It is read
	// only when a token names a key id that is not known yet. Optional.
	JWKSURL string `json:"jwksURL"`

	// JWKSFiles are key sets kept on disk. They hold keys the issuer has
	// since stopped publishing, so that older images still verify. Optional.
	JWKSFiles []string `json:"jwksFiles"`
}

type tokenVerifier struct {
	issuers map[string]*issuerKeys
}

func newTokenVerifier(opts []issuerOptions) (*tokenVerifier, error) {
	if len(opts) == 0 {
		return nil, errors.New("no token issuers configured")
	}
	t := &tokenVerifier{issuers: map[string]*issuerKeys{}}
	for _, opt := range opts {
		if opt.Issuer == "" {
			return nil, errors.New("token issuer must not be empty")
		}
		if _, exists := t.issuers[opt.Issuer]; exists {
			return nil, fmt.Errorf("token issuer %s is configured twice", opt.Issuer)
		}
		if opt.JWKSURL == "" && len(opt.JWKSFiles) == 0 {
			return nil, fmt.Errorf("token issuer %s needs jwksURL or jwksFiles", opt.Issuer)
		}
		if opt.JWKSURL != "" {
			if u, err := url.Parse(opt.JWKSURL); err != nil || u.Scheme != "https" {
				return nil, fmt.Errorf("token issuer %s: jwksURL must be an https URL", opt.Issuer)
			}
		}
		keys := &issuerKeys{
			issuer: opt.Issuer,
			url:    opt.JWKSURL,
			files:  opt.JWKSFiles,
			client: &http.Client{Timeout: keyFetchTimeout},
			keys:   map[string]*rsa.PublicKey{},
		}
		// A missing or broken key file must stop the verifier from starting:
		// without it, images signed under retired keys would be refused.
		if err := keys.loadFiles(); err != nil {
			return nil, fmt.Errorf("token issuer %s: %w", opt.Issuer, err)
		}
		t.issuers[opt.Issuer] = keys
	}
	return t, nil
}

// verify checks the token and returns its claims. The token's own expiry is
// not compared with the current time: the token is evidence of what the
// issuer stated when the image was signed, and images are admitted long after
// that. It is compared with the time of signing instead.
func (t *tokenVerifier) verify(ctx context.Context, raw, audience string, signedAt time.Time) (map[string]any, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	_, err := parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		issuer, _ := claims["iss"].(string)
		keys, ok := t.issuers[issuer]
		if !ok {
			return nil, fmt.Errorf("issuer %q is not on the issuer list", issuer)
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no key id")
		}
		return keys.key(ctx, kid)
	})
	if err != nil {
		return nil, err
	}

	audiences, err := claims.GetAudience()
	if err != nil || len(audiences) != 1 || audiences[0] != audience {
		return nil, fmt.Errorf("audience is %q, expected %q: the token was issued for a different image", []string(audiences), audience)
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return nil, errors.New("token has no usable iat claim")
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return nil, errors.New("token has no usable exp claim")
	}
	if signedAt.IsZero() {
		return nil, errors.New("signature has no signing time to compare the token with")
	}
	if signedAt.Before(issuedAt.Add(-signingTimeSkew)) || signedAt.After(expiresAt.Add(signingTimeSkew)) {
		return nil, fmt.Errorf("token was valid from %s to %s but the signature was made at %s",
			issuedAt.UTC().Format(time.RFC3339), expiresAt.UTC().Format(time.RFC3339), signedAt.UTC().Format(time.RFC3339))
	}
	return claims, nil
}

// issuerKeys holds every key seen for one issuer. Keys are only ever added.
type issuerKeys struct {
	issuer string
	url    string
	files  []string
	client *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

func (k *issuerKeys) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}

	// The files may have gained keys since they were last read.
	fileErr := k.loadFiles()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}

	var fetchErr error
	if k.url != "" && time.Since(k.lastFetch) >= keyFetchInterval {
		k.lastFetch = time.Now()
		if fetchErr = k.fetch(ctx); fetchErr == nil {
			if key, ok := k.keys[kid]; ok {
				return key, nil
			}
		}
	}
	if err := errors.Join(fileErr, fetchErr); err != nil {
		return nil, fmt.Errorf("issuer %s has no known key %q: %w", k.issuer, kid, err)
	}
	return nil, fmt.Errorf("issuer %s has no known key %q", k.issuer, kid)
}

func (k *issuerKeys) loadFiles() error {
	for _, path := range k.files {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}
		if err := k.add(data); err != nil {
			return fmt.Errorf("key file %s: %w", path, err)
		}
	}
	return nil
}

func (k *issuerKeys) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", k.url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetBytes))
	if err != nil {
		return err
	}
	return k.add(data)
}

// add merges the RSA keys of a JWKS document into the known keys.
func (k *issuerKeys) add(jwks []byte) error {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return fmt.Errorf("not a JSON key set: %w", err)
	}
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" || jwk.Kid == "" {
			continue
		}
		// A key id never changes its key. The first one seen stays.
		if _, known := k.keys[jwk.Kid]; known {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return fmt.Errorf("key %q: bad modulus: %w", jwk.Kid, err)
		}
		e, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return fmt.Errorf("key %q: bad exponent", jwk.Kid)
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("key %q: RSA key is shorter than 2048 bits", jwk.Kid)
		}
		k.keys[jwk.Kid] = key
	}
	return nil
}
