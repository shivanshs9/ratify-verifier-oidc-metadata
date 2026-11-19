package oidcmetadata

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	notationgo "github.com/notaryproject/notation-go"
	notationregistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"github.com/notaryproject/ratify-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	ciTestIssuer = "https://ci.example.test"
	ciTestRepo   = "registry.example.test/app/image"
)

// ciTestStore serves one signature manifest and its envelope blob.
type ciTestStore struct {
	content map[digest.Digest][]byte
}

func (s *ciTestStore) Resolve(context.Context, string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, fmt.Errorf("not used")
}

func (s *ciTestStore) ListReferrers(context.Context, string, []string, func([]ocispec.Descriptor) error) error {
	return fmt.Errorf("not used")
}

func (s *ciTestStore) FetchBlob(_ context.Context, _ string, desc ocispec.Descriptor) ([]byte, error) {
	return s.fetch(desc)
}

func (s *ciTestStore) FetchManifest(_ context.Context, _ string, desc ocispec.Descriptor) ([]byte, error) {
	return s.fetch(desc)
}

func (s *ciTestStore) fetch(desc ocispec.Descriptor) ([]byte, error) {
	if data, ok := s.content[desc.Digest]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("%s not found", desc.Digest)
}

// ciTestIssuerServer plays the CI system: it holds signing keys and publishes
// some of them.
type ciTestIssuerServer struct {
	server    *httptest.Server
	keys      map[string]*rsa.PrivateKey
	published atomic.Value // []string of key ids
	fetches   atomic.Int32
}

func newCITestIssuer(t *testing.T, kids ...string) *ciTestIssuerServer {
	t.Helper()
	issuer := &ciTestIssuerServer{keys: map[string]*rsa.PrivateKey{}}
	for _, kid := range kids {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		issuer.keys[kid] = key
	}
	issuer.published.Store(kids)
	issuer.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		issuer.fetches.Add(1)
		_, _ = w.Write(issuer.jwks(issuer.published.Load().([]string)...))
	}))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *ciTestIssuerServer) jwks(kids ...string) []byte {
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: []jwk{}}
	for _, kid := range kids {
		public := i.keys[kid].PublicKey
		set.Keys = append(set.Keys, jwk{
			Kty: "RSA",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		})
	}
	data, _ := json.Marshal(set)
	return data
}

// token issues an ID token the way GitHub does. Claims in overrides replace
// the defaults.
func (i *ciTestIssuerServer) token(t *testing.T, kid, audience string, overrides jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":           ciTestIssuer,
		"aud":           audience,
		"iat":           now.Add(-10 * time.Second).Unix(),
		"exp":           now.Add(5 * time.Minute).Unix(),
		"repository":    "example-org/example-repo",
		"repository_id": "123456789",
		"ref":           "refs/heads/release/sign-test",
		"event_name":    "push",
	}
	for name, value := range overrides {
		claims[name] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(i.keys[kid])
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func ciTestSubject() ocispec.Descriptor {
	image := []byte(`{"schemaVersion":2}`)
	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(image),
		Size:      int64(len(image)),
	}
}

// ciTestSign signs subject with the test leaf certificate and returns what
// Ratify hands to a verifier.
func ciTestSign(t *testing.T, subject ocispec.Descriptor, metadata map[string]string) *ratify.VerifyOptions {
	t.Helper()
	root, leaf := testhelper.GetRSARootCertificate(), testhelper.GetRSALeafCertificate()
	s, err := signer.NewGenericSigner(leaf.PrivateKey, []*x509.Certificate{leaf.Cert, root.Cert})
	if err != nil {
		t.Fatal(err)
	}
	signed := subject
	signed.Annotations = metadata
	envelope, _, err := s.Sign(context.Background(), signed, notationgo.SignerSignOptions{SignatureMediaType: jws.MediaTypeEnvelope})
	if err != nil {
		t.Fatal(err)
	}

	layer := ocispec.Descriptor{MediaType: jws.MediaTypeEnvelope, Digest: digest.FromBytes(envelope), Size: int64(len(envelope))}
	manifest, err := json.Marshal(ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: notationregistry.ArtifactTypeNotation,
		Layers:       []ocispec.Descriptor{layer},
		Subject:      &subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := ocispec.Descriptor{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: notationregistry.ArtifactTypeNotation,
		Digest:       digest.FromBytes(manifest),
		Size:         int64(len(manifest)),
	}
	return &ratify.VerifyOptions{
		Store:              &ciTestStore{content: map[digest.Digest][]byte{layer.Digest: envelope, artifact.Digest: manifest}},
		Repository:         ciTestRepo,
		SubjectDescriptor:  subject,
		ArtifactDescriptor: artifact,
	}
}

func ciTestCertificatePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// newCITestVerifier trusts the test root certificate and the test issuer.
// keyFiles are key sets on disk, as the deployment mounts them.
func newCITestVerifier(t *testing.T, issuer *ciTestIssuerServer, trusted *x509.Certificate, keyFiles ...string) *verifier {
	t.Helper()
	v, err := New("oidc-metadata", map[string]any{
		"certificates": []any{
			map[string]any{"type": "ca", "inline": map[string]any{"certs": ciTestCertificatePEM(trusted)}},
		},
		"issuers": []any{
			map[string]any{"issuer": ciTestIssuer, "jwksURL": issuer.server.URL, "jwksFiles": keyFiles},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cv := v.(*verifier)
	cv.tokens.issuers[ciTestIssuer].client = issuer.server.Client()
	return cv
}

func ciTestKeyFile(t *testing.T, jwks []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func ciTestVerify(t *testing.T, v *verifier, opts *ratify.VerifyOptions) *ratify.VerificationResult {
	t.Helper()
	result, err := v.Verify(context.Background(), opts)
	if err != nil {
		t.Fatalf("Verify returned a system error: %v", err)
	}
	return result
}

func ciTestExpectRefused(t *testing.T, result *ratify.VerificationResult, reason string) {
	t.Helper()
	if result.Err == nil {
		t.Fatalf("verification passed, expected a refusal containing %q", reason)
	}
	if !strings.Contains(result.Err.Error(), reason) {
		t.Fatalf("refused with %q, expected a reason containing %q", result.Err, reason)
	}
	if result.Detail != nil {
		t.Fatalf("a refused signature must not return claims, got %v", result.Detail)
	}
}

func TestOIDCMetadataAccepted(t *testing.T) {
	issuer := newCITestIssuer(t, "key-1")
	subject := ciTestSubject()
	v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert)

	token := issuer.token(t, "key-1", "oci-sign:"+subject.Digest.String(), nil)
	opts := ciTestSign(t, subject, map[string]string{"ci.id-token": token, "ci.issuer": ciTestIssuer})
	if !v.Verifiable(opts.ArtifactDescriptor) {
		t.Fatal("a notation signature must be verifiable")
	}
	result := ciTestVerify(t, v, opts)
	if result.Err != nil {
		t.Fatalf("verification failed: %v", result.Err)
	}

	// The policy reads the detail as JSON, so check it in that form.
	raw, err := json.Marshal(result.Detail)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Issuer string         `json:"issuer"`
		Raw    map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Issuer != ciTestIssuer {
		t.Errorf("issuer is %q, expected %q", detail.Issuer, ciTestIssuer)
	}
	for claim, expected := range map[string]string{
		"repository_id": "123456789",
		"ref":           "refs/heads/release/sign-test",
		"event_name":    "push",
	} {
		if detail.Raw[claim] != expected {
			t.Errorf("claim %s is %v, expected %q", claim, detail.Raw[claim], expected)
		}
	}
	if strings.Contains(string(raw), token) {
		t.Error("the raw token must not be returned")
	}
}

func TestOIDCMetadataRefused(t *testing.T) {
	issuer := newCITestIssuer(t, "key-1")
	stranger := newCITestIssuer(t, "key-1", "key-9")
	subject := ciTestSubject()
	audience := "oci-sign:" + subject.Digest.String()
	valid := issuer.token(t, "key-1", audience, nil)
	parts := strings.Split(valid, ".")

	edited, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	edited = []byte(strings.Replace(string(edited), "123456789", "987654321", 1))

	symmetric, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": ciTestIssuer, "aud": audience}).
		SignedString(issuer.jwks("key-1"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": ciTestIssuer, "aud": audience}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	hourAgo := time.Now().Add(-time.Hour)

	cases := []struct {
		name   string
		token  string
		reason string
	}{
		{"token for a different image", issuer.token(t, "key-1", "oci-sign:sha256:"+strings.Repeat("0", 64), nil), "different image"},
		{"token with the usual AWS audience", issuer.token(t, "key-1", "sts.amazonaws.com", nil), "different image"},
		{"token with a second audience", issuer.token(t, "key-1", "", jwt.MapClaims{"aud": []string{audience, "other"}}), "different image"},
		{"known key id, signed by another key", stranger.token(t, "key-1", audience, nil), "verification error"},
		{"key id the issuer does not publish", stranger.token(t, "key-9", audience, nil), `no known key "key-9"`},
		{"issuer not on the list", issuer.token(t, "key-1", audience, jwt.MapClaims{"iss": "https://act.example.test"}), "not on the issuer list"},
		{"claims edited after signing", parts[0] + "." + base64.RawURLEncoding.EncodeToString(edited) + "." + parts[2], "verification error"},
		{"symmetric algorithm", symmetric, "signing method HS256 is invalid"},
		{"algorithm none", unsigned, "signing method none is invalid"},
		{"not a token", "not-a-token", "malformed"},
		{"token that expired before signing", issuer.token(t, "key-1", audience, jwt.MapClaims{
			"iat": hourAgo.Unix(), "exp": hourAgo.Add(5 * time.Minute).Unix(),
		}), "the signature was made at"},
		{"token without expiry", issuer.token(t, "key-1", audience, jwt.MapClaims{"exp": nil}), "exp claim"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert)
			result := ciTestVerify(t, v, ciTestSign(t, subject, map[string]string{"ci.id-token": tc.token}))
			ciTestExpectRefused(t, result, tc.reason)
		})
	}

	t.Run("signature without a token", func(t *testing.T) {
		v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert)
		result := ciTestVerify(t, v, ciTestSign(t, subject, nil))
		ciTestExpectRefused(t, result, "carries no CI token")
	})

	t.Run("signing certificate that is not trusted", func(t *testing.T) {
		v := newCITestVerifier(t, issuer, testhelper.GetECRootCertificate().Cert)
		result := ciTestVerify(t, v, ciTestSign(t, subject, map[string]string{"ci.id-token": valid}))
		ciTestExpectRefused(t, result, "notation signature")
	})

	t.Run("signature copied from another image", func(t *testing.T) {
		v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert)
		opts := ciTestSign(t, subject, map[string]string{"ci.id-token": valid})
		other := []byte(`{"schemaVersion":2,"other":true}`)
		opts.SubjectDescriptor = ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    digest.FromBytes(other),
			Size:      int64(len(other)),
		}
		ciTestExpectRefused(t, ciTestVerify(t, v, opts), "notation signature")
	})
}

func TestOIDCMetadataKeyRotation(t *testing.T) {
	subject := ciTestSubject()
	audience := "oci-sign:" + subject.Digest.String()

	t.Run("retired key that is in the key file", func(t *testing.T) {
		issuer := newCITestIssuer(t, "old", "current")
		token := issuer.token(t, "old", audience, nil)
		archive := ciTestKeyFile(t, issuer.jwks("old"))
		issuer.published.Store([]string{"current"})

		v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert, archive)
		result := ciTestVerify(t, v, ciTestSign(t, subject, map[string]string{"ci.id-token": token}))
		if result.Err != nil {
			t.Fatalf("verification failed: %v", result.Err)
		}
		if n := issuer.fetches.Load(); n != 0 {
			t.Errorf("a key from the file must not cause a fetch, got %d", n)
		}
	})

	t.Run("retired key that is in no key file", func(t *testing.T) {
		issuer := newCITestIssuer(t, "old", "current")
		token := issuer.token(t, "old", audience, nil)
		issuer.published.Store([]string{"current"})

		v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert)
		result := ciTestVerify(t, v, ciTestSign(t, subject, map[string]string{"ci.id-token": token}))
		ciTestExpectRefused(t, result, `no known key "old"`)
	})

	t.Run("new key is fetched once", func(t *testing.T) {
		issuer := newCITestIssuer(t, "old", "new")
		archive := ciTestKeyFile(t, issuer.jwks("old"))
		v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert, archive)

		opts := ciTestSign(t, subject, map[string]string{"ci.id-token": issuer.token(t, "new", audience, nil)})
		for range 3 {
			if result := ciTestVerify(t, v, opts); result.Err != nil {
				t.Fatalf("verification failed: %v", result.Err)
			}
		}
		if n := issuer.fetches.Load(); n != 1 {
			t.Errorf("expected exactly one fetch of the issuer's keys, got %d", n)
		}
	})

	t.Run("key added to the key file while running", func(t *testing.T) {
		issuer := newCITestIssuer(t, "old", "added")
		issuer.published.Store([]string{})
		archive := ciTestKeyFile(t, issuer.jwks("old"))
		v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert, archive)

		if err := os.WriteFile(archive, issuer.jwks("old", "added"), 0o600); err != nil {
			t.Fatal(err)
		}
		opts := ciTestSign(t, subject, map[string]string{"ci.id-token": issuer.token(t, "added", audience, nil)})
		if result := ciTestVerify(t, v, opts); result.Err != nil {
			t.Fatalf("verification failed: %v", result.Err)
		}
	})

	t.Run("unknown key ids do not flood the issuer", func(t *testing.T) {
		issuer := newCITestIssuer(t, "current")
		stranger := newCITestIssuer(t, "bogus-1", "bogus-2")
		v := newCITestVerifier(t, issuer, testhelper.GetRSARootCertificate().Cert)
		for _, kid := range []string{"bogus-1", "bogus-2"} {
			opts := ciTestSign(t, subject, map[string]string{"ci.id-token": stranger.token(t, kid, audience, nil)})
			ciTestExpectRefused(t, ciTestVerify(t, v, opts), "no known key")
		}
		if n := issuer.fetches.Load(); n != 1 {
			t.Errorf("expected one fetch within the interval, got %d", n)
		}
	})

	t.Run("a fetched key set cannot replace a known key", func(t *testing.T) {
		issuer := newCITestIssuer(t, "key-1")
		stranger := newCITestIssuer(t, "key-1", "key-2")
		archive := ciTestKeyFile(t, issuer.jwks("key-1"))
		v := newCITestVerifier(t, stranger, testhelper.GetRSARootCertificate().Cert, archive)

		// Fetch the stranger's key set, which reuses the id "key-1".
		opts := ciTestSign(t, subject, map[string]string{"ci.id-token": stranger.token(t, "key-2", audience, nil)})
		if result := ciTestVerify(t, v, opts); result.Err != nil {
			t.Fatalf("verification failed: %v", result.Err)
		}
		opts = ciTestSign(t, subject, map[string]string{"ci.id-token": stranger.token(t, "key-1", audience, nil)})
		ciTestExpectRefused(t, ciTestVerify(t, v, opts), "verification error")
	})
}

func TestOIDCMetadataConfiguration(t *testing.T) {
	certificates := []any{
		map[string]any{"type": "ca", "inline": map[string]any{"certs": ciTestCertificatePEM(testhelper.GetRSARootCertificate().Cert)}},
	}
	cases := []struct {
		name    string
		issuers []any
		reason  string
	}{
		{"no issuers", nil, "no token issuers"},
		{"issuer without keys", []any{map[string]any{"issuer": ciTestIssuer}}, "needs jwksURL or jwksFiles"},
		{"plain http key URL", []any{map[string]any{"issuer": ciTestIssuer, "jwksURL": "http://ci.example.test/jwks"}}, "https"},
		{"missing key file", []any{map[string]any{"issuer": ciTestIssuer, "jwksFiles": []any{"/nonexistent/keys.json"}}}, "failed to read key file"},
		{"issuer listed twice", []any{
			map[string]any{"issuer": ciTestIssuer, "jwksURL": "https://ci.example.test/jwks"},
			map[string]any{"issuer": ciTestIssuer, "jwksURL": "https://ci.example.test/jwks"},
		}, "configured twice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("oidc-metadata", map[string]any{"certificates": certificates, "issuers": tc.issuers})
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("got %v, expected an error containing %q", err, tc.reason)
			}
		})
	}

	t.Run("weak key in a key file", func(t *testing.T) {
		weak, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		issuer := &ciTestIssuerServer{keys: map[string]*rsa.PrivateKey{"weak": weak}}
		_, err = New("oidc-metadata", map[string]any{
			"certificates": certificates,
			"issuers":      []any{map[string]any{"issuer": ciTestIssuer, "jwksFiles": []any{ciTestKeyFile(t, issuer.jwks("weak"))}}},
		})
		if err == nil || !strings.Contains(err.Error(), "shorter than 2048 bits") {
			t.Fatalf("got %v, expected the weak key to be refused", err)
		}
	})
}
