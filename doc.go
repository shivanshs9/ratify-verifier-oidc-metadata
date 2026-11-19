// Package oidcmetadata provides a Ratify v2 verifier that checks an OIDC ID
// token stored as signed metadata inside a Notary Project signature.
//
// The verifier is a Go library. An entrypoint binary that wants it imports
// the module for its side effects, or calls New directly. See the README in
// the module root for the parameters and the verification steps.
package oidcmetadata
