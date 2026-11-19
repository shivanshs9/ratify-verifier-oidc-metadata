package oidcmetadata

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

const trustStoreName = "ratify"

// certificateOptions is the certificate block of the verifier parameters.
// Only the inline PEM form is supported: this verifier is meant to be
// configured from the Executor CRD the same way the stock notation verifier is.
type certificateOptions struct {
	Type   string `json:"type"`
	Inline *struct {
		Certs string `json:"certs"`
	} `json:"inline"`
}

type pemTrustStore struct {
	certs map[truststore.Type][]*x509.Certificate
}

func (s *pemTrustStore) GetCertificates(_ context.Context, storeType truststore.Type, _ string) ([]*x509.Certificate, error) {
	certs, ok := s.certs[storeType]
	if !ok {
		return nil, fmt.Errorf("trust store type %s is not configured", storeType)
	}
	return certs, nil
}

func initTrustStore(opts []certificateOptions) (truststore.X509TrustStore, []truststore.Type, error) {
	if len(opts) == 0 {
		return nil, nil, fmt.Errorf("no trust store options provided")
	}
	store := &pemTrustStore{certs: map[truststore.Type][]*x509.Certificate{}}
	var types []truststore.Type
	seen := map[truststore.Type]struct{}{}
	for _, opt := range opts {
		storeType, err := parseTrustStoreType(opt.Type)
		if err != nil {
			return nil, nil, err
		}
		if _, dup := seen[storeType]; dup {
			return nil, nil, fmt.Errorf("duplicate trust store type %s", storeType)
		}
		seen[storeType] = struct{}{}
		if opt.Inline == nil || opt.Inline.Certs == "" {
			return nil, nil, fmt.Errorf("trust store type %s needs inline.certs", storeType)
		}
		certs, err := parseCertificatesPEM(opt.Inline.Certs)
		if err != nil {
			return nil, nil, fmt.Errorf("trust store type %s: %w", storeType, err)
		}
		if err := truststore.ValidateCertificates(certs); err != nil {
			return nil, nil, fmt.Errorf("trust store type %s: %w", storeType, err)
		}
		store.certs[storeType] = certs
		types = append(types, storeType)
	}
	return store, types, nil
}

func parseTrustStoreType(raw string) (truststore.Type, error) {
	if raw == "" {
		raw = string(truststore.TypeCA)
	}
	storeType := truststore.Type(raw)
	switch storeType {
	case truststore.TypeCA, truststore.TypeTSA, truststore.TypeSigningAuthority:
		return storeType, nil
	default:
		return "", fmt.Errorf("invalid trust store type %s", raw)
	}
}

func parseCertificatesPEM(raw string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(raw)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in PEM data")
	}
	return certs, nil
}

func initTrustPolicyDocument(scopes, trustedIdentities []string, storeTypes []truststore.Type) *trustpolicy.Document {
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	if len(trustedIdentities) == 0 {
		trustedIdentities = []string{"*"}
	}
	names := make([]string, len(storeTypes))
	for i, storeType := range storeTypes {
		names[i] = fmt.Sprintf("%s:%s", storeType, trustStoreName)
	}
	return &trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{{
			Name:                  "default",
			RegistryScopes:        scopes,
			SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
			TrustStores:           names,
			TrustedIdentities:     trustedIdentities,
		}},
	}
}
