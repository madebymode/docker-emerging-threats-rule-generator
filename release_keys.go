//go:build native

package main

import _ "embed"

// releaseSigningKeysPEM holds the Ed25519 public keys (PEM, from
// `openssl pkey -pubout`) that self-update accepts for release manifests.
// While rotating, list the new key first and keep the old one after it; CI
// checks signatures against the first key. With no keys, self-update refuses
// every release.
//
//go:embed release-signing.pub
var releaseSigningKeysPEM []byte
