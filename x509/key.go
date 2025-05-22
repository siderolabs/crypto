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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

// Ed25519Key represents an Ed25519 key.
type Ed25519Key struct {
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
	PublicKeyPEM  []byte
	PrivateKeyPEM []byte
}

// RSAKey represents an RSA key.
type RSAKey struct {
	keyRSA       *rsa.PrivateKey
	KeyPEM       []byte
	PublicKeyPEM []byte
}

// ECDSAKey represents an ECDSA key.
type ECDSAKey struct {
	keyEC        *ecdsa.PrivateKey
	KeyPEM       []byte
	PublicKeyPEM []byte
}

// Key is a common interface implemented by RSAKey, ECDSAKey and Ed25519Key.
type Key interface {
	GetPrivateKeyPEM() []byte
	GetPublicKeyPEM() []byte
}

// PEMEncodedKey represents a PEM encoded private key.
type PEMEncodedKey struct {
	Key []byte `json:"Key"`
}

// NewECDSAKey generates an ECDSA key pair.
func NewECDSAKey() (*ECDSAKey, error) {
	keyEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(keyEC)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(keyEC.Public())
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeECPrivate,
		Bytes: keyBytes,
	})

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeECPublic,
		Bytes: publicKeyBytes,
	})

	key := &ECDSAKey{
		keyEC:        keyEC,
		KeyPEM:       keyPEM,
		PublicKeyPEM: publicKeyPEM,
	}

	return key, nil
}

// GetPrivateKeyPEM implements Key interface.
func (k *ECDSAKey) GetPrivateKeyPEM() []byte {
	return k.KeyPEM
}

// GetPublicKeyPEM implements Key interface.
func (k *ECDSAKey) GetPublicKeyPEM() []byte {
	return k.PublicKeyPEM
}

// NewEd25519Key generates an Ed25519 key pair.
func NewEd25519Key() (*Ed25519Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeEd25519Public,
		Bytes: pubBytes,
	})

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeEd25519Private,
		Bytes: privBytes,
	})

	key := &Ed25519Key{
		PublicKey:     pub,
		PrivateKey:    priv,
		PublicKeyPEM:  pubPEM,
		PrivateKeyPEM: privPEM,
	}

	return key, nil
}

// GetPrivateKeyPEM implements Key interface.
func (k *Ed25519Key) GetPrivateKeyPEM() []byte {
	return k.PrivateKeyPEM
}

// GetPublicKeyPEM implements Key interface.
func (k *Ed25519Key) GetPublicKeyPEM() []byte {
	return k.PublicKeyPEM
}

// NewRSAKey generates an RSA key pair.
func NewRSAKey() (*RSAKey, error) {
	keyRSA, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(keyRSA)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeRSAPrivate,
		Bytes: keyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&keyRSA.PublicKey)
	if err != nil {
		return nil, err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeRSAPublic,
		Bytes: publicKeyBytes,
	})

	key := &RSAKey{
		keyRSA:       keyRSA,
		KeyPEM:       keyPEM,
		PublicKeyPEM: publicKeyPEM,
	}

	return key, nil
}

// GetPrivateKeyPEM implements Key interface.
func (k *RSAKey) GetPrivateKeyPEM() []byte {
	return k.KeyPEM
}

// GetPublicKeyPEM implements Key interface.
func (k *RSAKey) GetPublicKeyPEM() []byte {
	return k.PublicKeyPEM
}

// NewKeyFromFile loads a PEM-encoded key from a file.
func NewKeyFromFile(keyPath string) (*PEMEncodedKey, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return &PEMEncodedKey{
		Key: keyBytes,
	}, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for
// PEMEncodedKey. It is expected that the Key is a base64
// encoded string in the YAML file. This function decodes the strings into byte
// slices.
func (p *PEMEncodedKey) UnmarshalYAML(unmarshal func(any) error) error {
	var aux struct {
		Key string `yaml:"key"`
	}

	if err := unmarshal(&aux); err != nil {
		return err
	}

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
func (p *PEMEncodedKey) MarshalYAML() (any, error) {
	var aux struct {
		Key string `yaml:"key"`
	}

	if string(p.Key) == Redacted {
		aux.Key = Redacted
	} else {
		aux.Key = base64.StdEncoding.EncodeToString(p.Key)
	}

	return aux, nil
}

// GetKey parses one of RSAKey, ECDSAKey or Ed25519Key.
func (p *PEMEncodedKey) GetKey() (Key, error) { //nolint:ireturn
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case PEMTypeRSAPrivate:
		return p.GetRSAKey()
	case PEMTypeECPrivate:
		return p.GetECDSAKey()
	case PEMTypeEd25519Private:
		return p.GetEd25519Key()
	case PEMTypePrivate:
		return p.GetPrivateKey()
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

// GetRSAKey parses PEM-encoded RSA key.
func (p *PEMEncodedKey) GetRSAKey() (*RSAKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeRSAPublic,
		Bytes: publicKeyBytes,
	})

	return &RSAKey{
		keyRSA:       key,
		KeyPEM:       p.Key,
		PublicKeyPEM: publicKeyPEM,
	}, nil
}

// GetPrivateKey parses generic PEM-encoded key.
func (p *PEMEncodedKey) GetPrivateKey() (Key, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	switch key := key.(type) {
	case *rsa.PrivateKey:
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encode public key: %w", err)
		}

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  PEMTypeRSAPublic,
			Bytes: publicKeyBytes,
		})

		return &RSAKey{
			keyRSA:       key,
			KeyPEM:       p.Key,
			PublicKeyPEM: publicKeyPEM,
		}, nil
	case *ecdsa.PrivateKey:
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return nil, fmt.Errorf("failed to encode public key: %w", err)
		}

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  PEMTypeECPublic,
			Bytes: publicKeyBytes,
		})

		return &ECDSAKey{
			keyEC:        key,
			KeyPEM:       p.Key,
			PublicKeyPEM: publicKeyPEM,
		}, nil
	case ed25519.PrivateKey:
		publicKey := key.Public()

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encode public key: %w", err)
		}

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  PEMTypeEd25519Public,
			Bytes: publicKeyBytes,
		})

		return &Ed25519Key{
			PrivateKey:    key,
			PublicKey:     publicKey.(ed25519.PublicKey), //nolint:forcetypeassert,errcheck
			PrivateKeyPEM: p.Key,
			PublicKeyPEM:  publicKeyPEM,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// GetEd25519Key parses PEM-encoded Ed25519 key.
func (p *PEMEncodedKey) GetEd25519Key() (*Ed25519Key, error) {
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

	publicKey := ed25519Key.Public()

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed encoding public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeEd25519Public,
		Bytes: pubBytes,
	})

	return &Ed25519Key{
		PrivateKey:    ed25519Key,
		PublicKey:     publicKey.(ed25519.PublicKey), //nolint:forcetypeassert,errcheck
		PrivateKeyPEM: p.Key,
		PublicKeyPEM:  pubPEM,
	}, nil
}

// GetECDSAKey parses PEM-encoded ECDSA key.
func (p *PEMEncodedKey) GetECDSAKey() (*ECDSAKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	ecdsaKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA key: %w", err)
	}

	publicKey := ecdsaKey.Public()

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed encoding public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeECPublic,
		Bytes: pubBytes,
	})

	return &ECDSAKey{
		keyEC:        ecdsaKey,
		KeyPEM:       p.Key,
		PublicKeyPEM: pubPEM,
	}, nil
}

// DeepCopy implements DeepCopy interface.
func (p *PEMEncodedKey) DeepCopy() *PEMEncodedKey {
	if p == nil {
		return nil
	}

	out := new(PEMEncodedKey)
	p.DeepCopyInto(out)

	return out
}

// DeepCopyInto implements DeepCopy interface.
func (p *PEMEncodedKey) DeepCopyInto(out *PEMEncodedKey) {
	if p.Key != nil {
		out.Key = make([]byte, len(p.Key))
		copy(out.Key, p.Key)
	}
}
