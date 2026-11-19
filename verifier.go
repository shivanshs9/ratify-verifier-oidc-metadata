package oidcmetadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	notationgo "github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	notationregistry "github.com/notaryproject/notation-go/registry"
	notationverifier "github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// Type is the verifier type string used in Executor configuration.
	Type = "oidc-metadata"

	defaultMetadataKey    = "ci.id-token"
	defaultAudiencePrefix = "oci-sign:"
)

type options struct {
	Scopes            []string             `json:"scopes"`
	TrustedIdentities []string             `json:"trustedIdentities"`
	Certificates      []certificateOptions `json:"certificates"`
	PluginDirectory   string               `json:"pluginDirectory"`
	PluginConfig      map[string]string    `json:"pluginConfig"`
	MetadataKey       string               `json:"metadataKey"`
	AudiencePrefix    string               `json:"audiencePrefix"`
	Issuers           []issuerOptions      `json:"issuers"`
}

type detail struct {
	Issuer           string            `json:"issuer"`
	Claims           map[string]any    `json:"claims"`
	SigningTime      string            `json:"signingTime"`
	SignerSubject    string            `json:"signerSubject"`
	SignedAttributes map[string]string `json:"signedAttributes,omitempty"`
}

type verifier struct {
	name           string
	metadataKey    string
	audiencePrefix string
	pluginConfig   map[string]string
	signatures     notationgo.Verifier
	tokens         *tokenVerifier
}

// New builds an oidc-metadata verifier from the Executor parameters.
func New(name string, parameters any) (ratify.Verifier, error) {
	raw, err := json.Marshal(parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier parameters: %w", err)
	}
	var params options
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verifier parameters: %w", err)
	}

	trustStore, types, err := initTrustStore(params.Certificates)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize trust store: %w", err)
	}
	var plugins plugin.Manager
	if params.PluginDirectory != "" {
		info, err := os.Stat(params.PluginDirectory)
		if err != nil {
			return nil, fmt.Errorf("failed to access plugin directory %q: %w", params.PluginDirectory, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("plugin directory %q is not a directory", params.PluginDirectory)
		}
		plugins = plugin.NewCLIManager(dir.NewSysFS(params.PluginDirectory))
	}
	signatures, err := notationverifier.NewWithOptions(
		initTrustPolicyDocument(params.Scopes, params.TrustedIdentities, types),
		trustStore, plugins, notationverifier.VerifierOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create notation verifier: %w", err)
	}

	tokens, err := newTokenVerifier(params.Issuers)
	if err != nil {
		return nil, err
	}

	v := &verifier{
		name:           name,
		metadataKey:    params.MetadataKey,
		audiencePrefix: params.AudiencePrefix,
		pluginConfig:   params.PluginConfig,
		signatures:     signatures,
		tokens:         tokens,
	}
	if v.metadataKey == "" {
		v.metadataKey = defaultMetadataKey
	}
	if v.audiencePrefix == "" {
		v.audiencePrefix = defaultAudiencePrefix
	}
	return v, nil
}

func (v *verifier) Name() string { return v.name }
func (v *verifier) Type() string { return Type }

func (v *verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == notationregistry.ArtifactTypeNotation && artifact.MediaType == ocispec.MediaTypeImageManifest
}

func (v *verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	envelope, mediaType, err := fetchSignatureEnvelope(ctx, opts)
	if err != nil {
		return nil, err
	}

	result := &ratify.VerificationResult{Verifier: v}
	digest := opts.SubjectDescriptor.Digest.String()
	outcome, err := v.signatures.Verify(ctx, opts.SubjectDescriptor, envelope, notationgo.VerifierVerifyOptions{
		SignatureMediaType: mediaType,
		ArtifactReference:  opts.Repository + "@" + digest,
		PluginConfig:       v.pluginConfig,
	})
	if err != nil {
		result.Err = fmt.Errorf("notation signature: %w", err)
		return result, nil
	}

	metadata, err := outcome.UserMetadata()
	if err != nil {
		result.Err = err
		return result, nil
	}
	token := metadata[v.metadataKey]
	if token == "" {
		result.Err = fmt.Errorf("signature is valid but carries no CI token in metadata key %q", v.metadataKey)
		return result, nil
	}

	signer := outcome.EnvelopeContent.SignerInfo
	signedAt := signer.SignedAttributes.SigningTime
	claims, err := v.tokens.verify(ctx, token, v.audiencePrefix+digest, signedAt)
	if err != nil {
		result.Err = fmt.Errorf("CI token: %w", err)
		return result, nil
	}

	d := detail{
		Claims:      claims,
		SigningTime: signedAt.UTC().Format(time.RFC3339),
	}
	d.Issuer, _ = claims["iss"].(string)
	if len(signer.CertificateChain) > 0 {
		d.SignerSubject = signer.CertificateChain[0].Subject.String()
	}
	for _, attribute := range signer.SignedAttributes.ExtendedAttributes {
		key, isKey := attribute.Key.(string)
		value, isValue := attribute.Value.(string)
		if isKey && isValue {
			if d.SignedAttributes == nil {
				d.SignedAttributes = map[string]string{}
			}
			d.SignedAttributes[key] = value
		}
	}
	result.Detail = d
	result.Description = "Notation signature and CI token verification succeeded"
	return result, nil
}

func fetchSignatureEnvelope(ctx context.Context, opts *ratify.VerifyOptions) ([]byte, string, error) {
	manifestBytes, err := opts.Store.FetchManifest(ctx, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch signature manifest: %w", err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal signature manifest: %w", err)
	}
	if len(manifest.Layers) != 1 {
		return nil, "", errors.New("notation signature manifest requires exactly one signature envelope blob")
	}
	envelope, err := opts.Store.FetchBlob(ctx, opts.Repository, manifest.Layers[0])
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch signature blob: %w", err)
	}
	return envelope, manifest.Layers[0].MediaType, nil
}
