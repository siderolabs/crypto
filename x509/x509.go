// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package x509 provides wrapper around standard crypto/* packages.
package x509

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
)

// Redacted is a special string that is used to indicate that a private key should be YAML-marshaled without the base64 encoding.
//
// If the value of a private key is exactly this string (in bytes), it will be marshaled as-is into YAML, without the base64 encoding.
const Redacted = "******"

// NewSerialNumber generates a random serial number for an X.509 certificate.
func NewSerialNumber() (*big.Int, error) {
	snLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	sn, err := rand.Int(rand.Reader, snLimit)
	if err != nil {
		return nil, err
	}

	return sn, nil
}

// NewSubjectKeyID generates a Subject Key Identifier (SKID) for an X.509 certificate.
func NewSubjectKeyID() ([]byte, error) {
	// The SKID is typically the SHA-1 hash of the public key, but SHA-1 is not FIPS-140-3 compliant.
	//
	// From the RFC 5280, Section 4.2.1.2:
	// The subject key identifier extension provides a means of identifying
	// certificates that contain a particular public key.
	//
	// For CA certificates, subject key identifiers SHOULD be derived from
	// the public key or a method that generates unique values.
	// ....
	//
	// Other methods of generating unique numbers are also acceptable.
	skid := make([]byte, 20) // SHA-1 produces a 20-byte hash
	if _, err := rand.Read(skid); err != nil {
		return nil, err
	}

	return skid, nil
}

// Hash calculates the SHA-256 hash of the Subject Public Key Information (SPKI)
// object in an x509 certificate (in DER encoding). It returns the full hash as
// a hex encoded string (suitable for passing to Set.Allow). See
// https://github.com/kubernetes/kubernetes/blob/f557e0f7e3ee9089769ed3f03187fdd4acbb9ac1/cmd/kubeadm/app/util/pubkeypin/pubkeypin.go
func Hash(crt *x509.Certificate) string {
	spkiHash := sha256.Sum256(crt.RawSubjectPublicKeyInfo)

	return "sha256" + ":" + strings.ToLower(hex.EncodeToString(spkiHash[:]))
}
