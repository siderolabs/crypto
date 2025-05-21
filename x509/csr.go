// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// CertificateSigningRequest represents a CSR.
type CertificateSigningRequest struct {
	X509CertificateRequest    *x509.CertificateRequest
	X509CertificateRequestPEM []byte
}

// NewCertificateSigningRequest creates a CSR. If the IPAddresses or DNSNames options are not
// specified, the CSR will be generated with the default values set in
// NewDefaultOptions.
func NewCertificateSigningRequest(key any, setters ...Option) (*CertificateSigningRequest, error) {
	opts := NewDefaultOptions(setters...)

	template := &x509.CertificateRequest{
		IPAddresses: opts.IPAddresses,
		DNSNames:    opts.DNSNames,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organizations,
		},
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		template.SignatureAlgorithm = x509.SHA512WithRSA
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P224(), elliptic.P256():
			template.SignatureAlgorithm = x509.ECDSAWithSHA256
		case elliptic.P384():
			template.SignatureAlgorithm = x509.ECDSAWithSHA384
		case elliptic.P521():
			template.SignatureAlgorithm = x509.ECDSAWithSHA512
		default:
			return nil, fmt.Errorf("unsupported ECDSA key curve: %s", k.Curve)
		}
	case ed25519.PrivateKey:
		template.SignatureAlgorithm = x509.PureEd25519
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificateRequest,
		Bytes: csrBytes,
	})

	csr := &CertificateSigningRequest{
		X509CertificateRequest:    template,
		X509CertificateRequestPEM: csrPEM,
	}

	return csr, nil
}

// NewEd25519CSRAndIdentity generates and PEM encoded certificate and key, along with a
// CSR for the generated key.
func NewEd25519CSRAndIdentity(setters ...Option) (*CertificateSigningRequest, *PEMEncodedCertificateAndKey, error) {
	key, err := NewEd25519Key()
	if err != nil {
		return nil, nil, err
	}

	identity := &PEMEncodedCertificateAndKey{
		Key: key.PrivateKeyPEM,
	}

	csr, err := NewCertificateSigningRequest(key.PrivateKey, setters...)
	if err != nil {
		return nil, nil, err
	}

	return csr, identity, nil
}

// NewRSACSRAndIdentity generates and PEM encoded certificate and key, along with a
// CSR for the generated key.
func NewRSACSRAndIdentity(setters ...Option) (*CertificateSigningRequest, *PEMEncodedCertificateAndKey, error) {
	key, err := NewRSAKey()
	if err != nil {
		return nil, nil, err
	}

	identity := &PEMEncodedCertificateAndKey{
		Key: key.KeyPEM,
	}

	csr, err := NewCertificateSigningRequest(key.keyRSA, setters...)
	if err != nil {
		return nil, nil, err
	}

	return csr, identity, nil
}

// NewECDSACSRAndIdentity generates and PEM encoded certificate and key, along with a
// CSR for the generated key.
func NewECDSACSRAndIdentity(setters ...Option) (*CertificateSigningRequest, *PEMEncodedCertificateAndKey, error) {
	key, err := NewECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	identity := &PEMEncodedCertificateAndKey{
		Key: key.KeyPEM,
	}

	csr, err := NewCertificateSigningRequest(key.keyEC, setters...)
	if err != nil {
		return nil, nil, err
	}

	return csr, identity, nil
}
