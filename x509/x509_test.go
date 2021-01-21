// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//nolint: scopelint
package x509_test

import (
	"testing"

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

	ed25519ca, err := x509.NewSelfSignedCertificateAuthority(x509.RSA(false))
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
				ca:      rsaCA,
				setters: []x509.Option{x509.RSA(true)},
			},
			wantErr: false,
		},
		{
			name: "valid Ed25519",
			args: args{
				ca:      ed25519ca,
				setters: []x509.Option{x509.RSA(false)},
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
