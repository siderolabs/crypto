// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// PEMEncodedCertificateAndKey represents a PEM encoded certificate and
// private key pair.
type PEMEncodedCertificateAndKey struct {
	Crt []byte `json:"Crt"`
	Key []byte `json:"Key"`
}

// NewCertificateAndKeyFromFiles initializes and returns a
// PEMEncodedCertificateAndKey from the path to a crt and key.
func NewCertificateAndKeyFromFiles(crt, key string) (*PEMEncodedCertificateAndKey, error) {
	p := &PEMEncodedCertificateAndKey{}

	crtBytes, err := os.ReadFile(crt)
	if err != nil {
		return nil, err
	}

	p.Crt = crtBytes

	keyBytes, err := os.ReadFile(key)
	if err != nil {
		return nil, err
	}

	p.Key = keyBytes

	return p, nil
}

// NewCertificateAndKeyFromCertificateAuthority initializes and returns a
// PEMEncodedCertificateAndKey from the CertificateAuthority.
func NewCertificateAndKeyFromCertificateAuthority(ca *CertificateAuthority) *PEMEncodedCertificateAndKey {
	return &PEMEncodedCertificateAndKey{
		Crt: ca.CrtPEM,
		Key: ca.KeyPEM,
	}
}

// NewCertificateAndKeyFromKeyPair initializes and returns a
// PEMEncodedCertificateAndKey from the KeyPair.
func NewCertificateAndKeyFromKeyPair(keyPair *KeyPair) *PEMEncodedCertificateAndKey {
	return &PEMEncodedCertificateAndKey{
		Crt: keyPair.CrtPEM,
		Key: keyPair.KeyPEM,
	}
}

// NewCertificateAndKey generates a new key and certificate signed by a CA.
func NewCertificateAndKey(crt *x509.Certificate, key any, setters ...Option) (*PEMEncodedCertificateAndKey, error) {
	var (
		k, priv  any
		pemBytes []byte
		err      error
	)

	switch key.(type) {
	case *rsa.PrivateKey:
		k, err = NewRSAKey()
		if err != nil {
			return nil, fmt.Errorf("failed to create new RSA key: %w", err)
		}

		priv = k.(*RSAKey).keyRSA     //nolint:forcetypeassert,errcheck
		pemBytes = k.(*RSAKey).KeyPEM //nolint:forcetypeassert,errcheck
	case *ecdsa.PrivateKey:
		k, err = NewECDSAKey()
		if err != nil {
			return nil, fmt.Errorf("failed to create new RSA key: %w", err)
		}

		priv = k.(*ECDSAKey).keyEC      //nolint:forcetypeassert,errcheck
		pemBytes = k.(*ECDSAKey).KeyPEM //nolint:forcetypeassert,errcheck
	case ed25519.PrivateKey:
		k, err = NewEd25519Key()
		if err != nil {
			return nil, fmt.Errorf("failed to create new Ed25519 key: %w", err)
		}

		priv = k.(*Ed25519Key).PrivateKey        //nolint:forcetypeassert,errcheck
		pemBytes = k.(*Ed25519Key).PrivateKeyPEM //nolint:forcetypeassert,errcheck
	}

	csr, err := NewCertificateSigningRequest(priv, setters...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	block, _ := pem.Decode(csr.X509CertificateRequestPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM encoded CSR")
	}

	cr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	c, err := NewCertificateFromCSR(crt, key, cr, setters...)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate from CSR: %w", err)
	}

	p := &PEMEncodedCertificateAndKey{
		Crt: c.X509CertificatePEM,
		Key: pemBytes,
	}

	return p, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for
// PEMEncodedCertificateAndKey. It is expected that the Crt and Key are a base64
// encoded string in the YAML file. This function decodes the strings into byte
// slices.
func (p *PEMEncodedCertificateAndKey) UnmarshalYAML(unmarshal func(any) error) error {
	var aux struct {
		Crt string `yaml:"crt"`
		Key string `yaml:"key"`
	}

	if err := unmarshal(&aux); err != nil {
		return err
	}

	decodedCrt, err := base64.StdEncoding.DecodeString(aux.Crt)
	if err != nil {
		return err
	}

	p.Crt = decodedCrt

	if aux.Key == Redacted {
		p.Key = []byte(Redacted)
	} else {
		decodedKey, err := base64.StdEncoding.DecodeString(aux.Key)
		if err != nil {
			return err
		}

		p.Key = decodedKey
	}

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for
// PEMEncodedCertificateAndKey. It is expected that the Crt and Key are a base64
// encoded string in the YAML file. This function encodes the byte slices into
// strings.
func (p *PEMEncodedCertificateAndKey) MarshalYAML() (any, error) {
	var aux struct {
		Crt string `yaml:"crt"`
		Key string `yaml:"key"`
	}

	aux.Crt = base64.StdEncoding.EncodeToString(p.Crt)

	if string(p.Key) == Redacted {
		aux.Key = Redacted
	} else {
		aux.Key = base64.StdEncoding.EncodeToString(p.Key)
	}

	return aux, nil
}

// GetCert parses PEM-encoded certificate as x509.Certificate.
func (p *PEMEncodedCertificateAndKey) GetCert() (*x509.Certificate, error) {
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

// GetKey parses either RSA or Ed25519 PEM-encoded key.
func (p *PEMEncodedCertificateAndKey) GetKey() (any, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case PEMTypeRSAPrivate:
		return p.GetRSAKey()
	case PEMTypeEd25519Private:
		return p.GetEd25519Key()
	case PEMTypeECPrivate:
		return p.GetECDSAKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %q", block.Type)
	}
}

// GetRSAKey parses PEM-encoded RSA key.
func (p *PEMEncodedCertificateAndKey) GetRSAKey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}

	return key, nil
}

// GetEd25519Key parses PEM-encoded Ed25519 key.
func (p *PEMEncodedCertificateAndKey) GetEd25519Key() (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ed25519 key: %w", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)

	if !ok {
		return nil, fmt.Errorf("failed parsing Ed25519 key, got wrong key type")
	}

	return ed25519Key, nil
}

// GetECDSAKey parses PEM-encoded ECDSA key.
func (p *PEMEncodedCertificateAndKey) GetECDSAKey() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	ecdsaKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA key: %w", err)
	}

	return ecdsaKey, nil
}

// DeepCopy implements DeepCopy interface.
func (p *PEMEncodedCertificateAndKey) DeepCopy() *PEMEncodedCertificateAndKey {
	if p == nil {
		return nil
	}

	out := new(PEMEncodedCertificateAndKey)
	p.DeepCopyInto(out)

	return out
}

// DeepCopyInto implements DeepCopy interface.
func (p *PEMEncodedCertificateAndKey) DeepCopyInto(out *PEMEncodedCertificateAndKey) {
	if p.Crt != nil {
		out.Crt = make([]byte, len(p.Crt))
		copy(out.Crt, p.Crt)
	}

	if p.Key != nil {
		out.Key = make([]byte, len(p.Key))
		copy(out.Key, p.Key)
	}
}
