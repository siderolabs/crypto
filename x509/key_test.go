// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/siderolabs/crypto/x509"
)

//nolint:goconst
func TestNewKeyViaPEM(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

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

func TestNewKeyFromFile(t *testing.T) {
	t.Parallel()

	key, err := x509.NewRSAKey()
	require.NoError(t, err)

	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "key.pem"), key.KeyPEM, 0o600))

	loaded, err := x509.NewKeyFromFile(filepath.Join(tmpDir, "key.pem"))
	require.NoError(t, err)

	assert.Equal(t, key.KeyPEM, loaded.Key)

	_, err = loaded.GetRSAKey()
	require.NoError(t, err)
}

func TestPEMEncodedKeyRSA(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
