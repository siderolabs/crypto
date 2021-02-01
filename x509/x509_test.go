// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//nolint: scopelint,goconst
package x509_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/talos-systems/crypto/x509"
)

func TestNewKeyPair(t *testing.T) {
	rsaCA, err := x509.NewSelfSignedCertificateAuthority(x509.RSA(true))
	if err != nil {
		t.Fatal(err)
	}

	ed25519ca, err := x509.NewSelfSignedCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}

	ecdsaCA, err := x509.NewSelfSignedCertificateAuthority(x509.ECDSA(true))
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ca      *x509.CertificateAuthority
		setters []x509.Option
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid RSA",
			args: args{
				ca: rsaCA,
			},
			wantErr: false,
		},
		{
			name: "valid Ed25519",
			args: args{
				ca: ed25519ca,
			},
			wantErr: false,
		},
		{
			name: "valid ECDSA",
			args: args{
				ca: ecdsaCA,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := x509.NewKeyPair(tt.args.ca, tt.args.setters...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKeyPair() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
		})
	}
}

func TestNewKeyPairViaPEM(t *testing.T) {
	tests := []struct {
		name string
		opt  x509.Option
	}{
		{
			name: "valid RSA",
			opt:  x509.RSA(true),
		},
		{
			name: "valid Ed25519",
			opt:  x509.RSA(false),
		},
		{
			name: "valid ECDSA",
			opt:  x509.ECDSA(true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []x509.Option{
				tt.opt,
				x509.Organization("kubernetes"),
				x509.NotAfter(time.Now().Add(87600 * time.Hour)),
				x509.NotBefore(time.Now()),
			}

			ca, err := x509.NewSelfSignedCertificateAuthority(opts...)
			require.NoError(t, err)

			pemEncoded := &x509.PEMEncodedCertificateAndKey{
				Crt: ca.CrtPEM,
				Key: ca.KeyPEM,
			}

			ca, err = x509.NewCertificateAuthorityFromCertificateAndKey(pemEncoded)
			require.NoError(t, err)

			_, err = x509.NewKeyPair(ca)
			require.NoError(t, err)
		})
	}
}

func TestNewKeyViaPEM(t *testing.T) {
	tests := []struct {
		name string
		algo string
	}{
		{
			name: "RSA",
			algo: "rsa",
		},
		{
			name: "Ed25519",
			algo: "ed25519",
		},
		{
			name: "ECDSA",
			algo: "ecdsa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keyPEM *x509.PEMEncodedKey

			switch tt.algo {
			case "rsa":
				key, err := x509.NewRSAKey()
				require.NoError(t, err)

				keyPEM = &x509.PEMEncodedKey{
					Key: key.KeyPEM,
				}
			case "ed25519":
				key, err := x509.NewEd25519Key()
				require.NoError(t, err)

				keyPEM = &x509.PEMEncodedKey{
					Key: key.PrivateKeyPEM,
				}
			case "ecdsa":
				key, err := x509.NewECDSAKey()
				require.NoError(t, err)

				keyPEM = &x509.PEMEncodedKey{
					Key: key.KeyPEM,
				}
			}

			switch tt.algo {
			case "rsa":
				_, err := keyPEM.GetRSAKey()
				require.NoError(t, err)
			case "ed25519":
				_, err := keyPEM.GetEd25519Key()
				require.NoError(t, err)
			case "ecdsa":
				_, err := keyPEM.GetECDSAKey()
				require.NoError(t, err)
			}

			k, err := keyPEM.GetKey()
			require.NoError(t, err)

			switch tt.algo {
			case "rsa":
				assert.IsType(t, &x509.RSAKey{}, k)
			case "ed25519":
				assert.IsType(t, &x509.Ed25519Key{}, k)
			case "ecdsa":
				assert.IsType(t, &x509.ECDSAKey{}, k)
			}
		})
	}
}

func TestPEMEncodedKeyRSA(t *testing.T) {
	key, err := x509.NewRSAKey()
	require.NoError(t, err)

	encoded := &x509.PEMEncodedKey{
		Key: key.KeyPEM,
	}

	marshaled, err := yaml.Marshal(encoded)
	require.NoError(t, err)

	var decoded x509.PEMEncodedKey

	require.NoError(t, yaml.Unmarshal(marshaled, &decoded))

	decodedKey, err := decoded.GetRSAKey()
	require.NoError(t, err)

	assert.Equal(t, key.KeyPEM, decodedKey.KeyPEM)
	assert.Equal(t, key.PublicKeyPEM, decodedKey.PublicKeyPEM)
}

func TestPEMEncodedKeyEd25519(t *testing.T) {
	key, err := x509.NewEd25519Key()
	require.NoError(t, err)

	encoded := &x509.PEMEncodedKey{
		Key: key.PrivateKeyPEM,
	}

	marshaled, err := yaml.Marshal(encoded)
	require.NoError(t, err)

	var decoded x509.PEMEncodedKey

	require.NoError(t, yaml.Unmarshal(marshaled, &decoded))

	decodedKey, err := decoded.GetEd25519Key()
	require.NoError(t, err)

	assert.Equal(t, key.PrivateKey, decodedKey.PrivateKey)
	assert.Equal(t, key.PublicKey, decodedKey.PublicKey)
	assert.Equal(t, key.PrivateKeyPEM, decodedKey.PrivateKeyPEM)
	assert.Equal(t, key.PublicKeyPEM, decodedKey.PublicKeyPEM)
}

func TestPEMEncodedKeyECDSA(t *testing.T) {
	key, err := x509.NewECDSAKey()
	require.NoError(t, err)

	encoded := &x509.PEMEncodedKey{
		Key: key.KeyPEM,
	}

	marshaled, err := yaml.Marshal(encoded)
	require.NoError(t, err)

	var decoded x509.PEMEncodedKey

	require.NoError(t, yaml.Unmarshal(marshaled, &decoded))

	decodedKey, err := decoded.GetECDSAKey()
	require.NoError(t, err)

	assert.Equal(t, key.KeyPEM, decodedKey.KeyPEM)
	assert.Equal(t, key.PublicKeyPEM, decodedKey.PublicKeyPEM)
}
