// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Certificate represents an X.509 certificate.
type Certificate struct {
	X509Certificate    *x509.Certificate
	X509CertificatePEM []byte
}

// PEMEncodedCertificate represents a PEM encoded certificate.
type PEMEncodedCertificate struct {
	Crt []byte `json:"Crt"`
}

// NewCertificateFromCSR creates and signs X.509 certificate using the provided CSR.
func NewCertificateFromCSR(ca *x509.Certificate, key any, csr *x509.CertificateRequest, setters ...Option) (*Certificate, error) {
	opts := NewDefaultOptions(setters...)

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed verifying CSR signature: %w", err)
	}

	serialNumber, err := NewSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber:          serialNumber,
		Issuer:                ca.Subject,
		Subject:               csr.Subject,
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		KeyUsage:              opts.KeyUsage,
		ExtKeyUsage:           opts.ExtKeyUsage,
		BasicConstraintsValid: false,
		IsCA:                  false,
		IPAddresses:           csr.IPAddresses,
		DNSNames:              csr.DNSNames,
	}

	if opts.OverrideSubject != nil {
		opts.OverrideSubject(&template.Subject)
	}

	crtDER, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, key)
	if err != nil {
		return nil, err
	}

	x509Certificate, err := x509.ParseCertificate(crtDER)
	if err != nil {
		return nil, err
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: crtDER,
	})

	crt := &Certificate{
		X509Certificate:    x509Certificate,
		X509CertificatePEM: crtPEM,
	}

	return crt, nil
}

// NewCertificateFromCSRBytes creates a signed certificate using the provided
// certificate, key, and CSR.
func NewCertificateFromCSRBytes(ca, key, csr []byte, setters ...Option) (*Certificate, error) {
	caPemBlock, _ := pem.Decode(ca)
	if caPemBlock == nil {
		return nil, fmt.Errorf("failed to decode CA")
	}

	caCrt, err := x509.ParseCertificate(caPemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyPemBlock, _ := pem.Decode(key)
	if keyPemBlock == nil {
		return nil, fmt.Errorf("failed to decode key")
	}

	var caKey any

	switch keyPemBlock.Type {
	case PEMTypeRSAPrivate:
		caKey, err = x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
	case PEMTypeEd25519Private:
		caKey, err = x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes)
	case PEMTypeECPrivate:
		caKey, err = x509.ParseECPrivateKey(keyPemBlock.Bytes)
	case PEMTypePrivate:
		caKey, err = x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes)
	default:
		err = fmt.Errorf("unsupported PEM block: %v", keyPemBlock.Type)
	}

	if err != nil {
		return nil, err
	}

	csrPemBlock, _ := pem.Decode(csr)
	if csrPemBlock == nil {
		return nil, fmt.Errorf("failed to decode CSR")
	}

	request, err := x509.ParseCertificateRequest(csrPemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return NewCertificateFromCSR(caCrt, caKey, request, setters...)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for
// PEMEncodedCertificateAndKey. It is expected that the Crt is a base64
// encoded string in the YAML file. This function decodes the strings into byte
// slices.
func (p *PEMEncodedCertificate) UnmarshalYAML(unmarshal func(any) error) error {
	var aux struct {
		Crt string `yaml:"crt"`
	}

	if err := unmarshal(&aux); err != nil {
		return err
	}

	decodedCrt, err := base64.StdEncoding.DecodeString(aux.Crt)
	if err != nil {
		return err
	}

	p.Crt = decodedCrt

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for
// PEMEncodedCertificate. It is expected that the Crt is a base64
// encoded string in the YAML file. This function encodes the byte slices into
// strings.
func (p *PEMEncodedCertificate) MarshalYAML() (any, error) {
	var aux struct {
		Crt string `yaml:"crt"`
	}

	aux.Crt = base64.StdEncoding.EncodeToString(p.Crt)

	return aux, nil
}

// GetCert parses PEM-encoded certificate as x509.Certificate.
func (p *PEMEncodedCertificate) GetCert() (*x509.Certificate, error) {
	block, _ := pem.Decode(p.Crt)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// DeepCopy implements DeepCopy interface.
func (p *PEMEncodedCertificate) DeepCopy() *PEMEncodedCertificate {
	if p == nil {
		return nil
	}

	out := new(PEMEncodedCertificate)
	p.DeepCopyInto(out)

	return out
}

// DeepCopyInto implements DeepCopy interface.
func (p *PEMEncodedCertificate) DeepCopyInto(out *PEMEncodedCertificate) {
	if p.Crt != nil {
		out.Crt = make([]byte, len(p.Crt))
		copy(out.Crt, p.Crt)
	}
}
