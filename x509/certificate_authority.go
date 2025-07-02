// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// CertificateAuthority represents a CA.
type CertificateAuthority struct {
	Crt    *x509.Certificate
	CrtPEM []byte
	Key    any
	KeyPEM []byte
}

// NewSelfSignedCertificateAuthority creates a self-signed CA configured for
// server and client authentication.
func NewSelfSignedCertificateAuthority(setters ...Option) (*CertificateAuthority, error) {
	opts := NewDefaultOptions(setters...)

	serialNumber, err := NewSerialNumber()
	if err != nil {
		return nil, err
	}

	skID, err := NewSubjectKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to create subject key identifier: %w", err)
	}

	crt := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: opts.Organizations,
		},
		SubjectKeyId:          skID,
		SignatureAlgorithm:    opts.SignatureAlgorithm,
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		IPAddresses: opts.IPAddresses,
		DNSNames:    opts.DNSNames,
	}

	switch opts.SignatureAlgorithm { //nolint:exhaustive
	case x509.SHA512WithRSA, x509.SHA384WithRSA, x509.SHA256WithRSA:
		return RSACertificateAuthority(crt, opts)
	case x509.PureEd25519:
		return Ed25519CertificateAuthority(crt)
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return ECDSACertificateAuthority(crt)
	default:
		return nil, fmt.Errorf("unsupported signature algorithm")
	}
}

// NewCertificateAuthorityFromCertificateAndKey builds CertificateAuthority from PEMEncodedCertificateAndKey.
func NewCertificateAuthorityFromCertificateAndKey(p *PEMEncodedCertificateAndKey) (*CertificateAuthority, error) {
	ca := &CertificateAuthority{
		CrtPEM: p.Crt,
		KeyPEM: p.Key,
	}

	var err error
	if ca.Crt, err = p.GetCert(); err != nil {
		return nil, err
	}

	ca.Key, err = p.GetKey()
	if err != nil {
		return nil, err
	}

	return ca, nil
}

// RSACertificateAuthority creates an RSA CA.
func RSACertificateAuthority(template *x509.Certificate, opts *Options) (*CertificateAuthority, error) {
	key, err := rsa.GenerateKey(rand.Reader, opts.Bits)
	if err != nil {
		return nil, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeRSAPrivate,
		Bytes: keyBytes,
	})

	crtDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtDER)
	if err != nil {
		return nil, err
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: crtDER,
	})

	ca := &CertificateAuthority{
		Crt:    crt,
		CrtPEM: crtPEM,
		Key:    key,
		KeyPEM: keyPEM,
	}

	return ca, nil
}

// ECDSACertificateAuthority creates an ECDSA CA.
func ECDSACertificateAuthority(template *x509.Certificate) (*CertificateAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeECPrivate,
		Bytes: keyBytes,
	})

	crtDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtDER)
	if err != nil {
		return nil, err
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: crtDER,
	})

	ca := &CertificateAuthority{
		Crt:    crt,
		CrtPEM: crtPEM,
		Key:    key,
		KeyPEM: keyPEM,
	}

	return ca, nil
}

// Ed25519CertificateAuthority creates an Ed25519 CA.
func Ed25519CertificateAuthority(template *x509.Certificate) (*CertificateAuthority, error) {
	key, err := NewEd25519Key()
	if err != nil {
		return nil, fmt.Errorf("failed to create new Ed25519 key: %w", err)
	}

	crtDER, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey, key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ed25519 CA certificate: %w", err)
	}

	crt, err := x509.ParseCertificate(crtDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ed25519 CA certificate: %w", err)
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: crtDER,
	})

	ca := &CertificateAuthority{
		Crt:    crt,
		CrtPEM: crtPEM,
		Key:    key,
		KeyPEM: key.PrivateKeyPEM,
	}

	return ca, nil
}
