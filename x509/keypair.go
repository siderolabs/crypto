// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// KeyPair represents a certificate and key pair.
type KeyPair struct {
	*tls.Certificate

	CrtPEM []byte
	KeyPEM []byte
}

// NewKeyPair generates a certificate signed by the provided CA, and a private
// key. The certifcate and private key are then used to create a
// tls.X509KeyPair.
func NewKeyPair(ca *CertificateAuthority, setters ...Option) (*KeyPair, error) {
	var (
		csr      *CertificateSigningRequest
		identity *PEMEncodedCertificateAndKey
		err      error
	)

	switch ca.Crt.SignatureAlgorithm { //nolint:exhaustive
	case x509.SHA512WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA:
		csr, identity, err = NewRSACSRAndIdentity(setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create RSA CSR and identity: %w", err)
		}
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		// no matter what is the ECDSA algorithm for the CA, certificate generated will be ECDSA-P256-SHA256
		csr, identity, err = NewECDSACSRAndIdentity(setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA CSR and identity: %w", err)
		}
	case x509.PureEd25519:
		csr, identity, err = NewEd25519CSRAndIdentity(setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create Ed25519 CSR and identity: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", ca.Crt.SignatureAlgorithm)
	}

	crt, err := NewCertificateFromCSRBytes(ca.CrtPEM, ca.KeyPEM, csr.X509CertificateRequestPEM, setters...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new certificate: %w", err)
	}

	x509KeyPair, err := tls.X509KeyPair(crt.X509CertificatePEM, identity.Key)
	if err != nil {
		return nil, err
	}

	keypair := &KeyPair{
		Certificate: &x509KeyPair,
		CrtPEM:      crt.X509CertificatePEM,
		KeyPEM:      identity.Key,
	}

	return keypair, nil
}
