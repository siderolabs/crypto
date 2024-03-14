// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/siderolabs/crypto/x509"
)

func TestNewKeyPair(t *testing.T) {
	t.Parallel()

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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := x509.NewKeyPair(tt.args.ca, tt.args.setters...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKeyPair() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
		})
	}
}

func TestNewKeyPairViaPEM(t *testing.T) {
	t.Parallel()

	tests := []struct { //nolint:govet
		name            string
		opt             x509.Option
		expectedSigAlgo stdx509.SignatureAlgorithm
	}{
		{
			name:            "valid RSA",
			opt:             x509.RSA(true),
			expectedSigAlgo: stdx509.SHA512WithRSA,
		},
		{
			name:            "valid RSA-SHA256",
			opt:             func(opts *x509.Options) { opts.SignatureAlgorithm = stdx509.SHA256WithRSA },
			expectedSigAlgo: stdx509.SHA256WithRSA,
		},
		{
			name:            "valid Ed25519",
			opt:             x509.RSA(false),
			expectedSigAlgo: stdx509.PureEd25519,
		},
		{
			name:            "valid ECDSA",
			opt:             x509.ECDSA(true),
			expectedSigAlgo: stdx509.ECDSAWithSHA256,
		},
		{
			name:            "valid ECDSA with SHA512",
			opt:             x509.ECDSASHA512(true),
			expectedSigAlgo: stdx509.ECDSAWithSHA512,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := []x509.Option{
				tt.opt,
				x509.Organization("kubernetes"),
				x509.NotAfter(time.Now().Add(87600 * time.Hour)),
				x509.NotBefore(time.Now()),
			}

			ca, err := x509.NewSelfSignedCertificateAuthority(opts...)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedSigAlgo, ca.Crt.SignatureAlgorithm)

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
		tt := tt
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

func TestNewCertificateFromCSR(t *testing.T) {
	t.Parallel()

	ca, err := x509.NewSelfSignedCertificateAuthority(x509.ECDSA(true))
	require.NoError(t, err)

	csr, _, err := x509.NewECDSACSRAndIdentity(x509.Organization("os:admin"))
	require.NoError(t, err)

	// sign the CSR usual way
	crt1, err := x509.NewCertificateFromCSRBytes(ca.CrtPEM, ca.KeyPEM, csr.X509CertificateRequestPEM)
	require.NoError(t, err)

	// sign the CSR with overrides
	crt2, err := x509.NewCertificateFromCSRBytes(ca.CrtPEM, ca.KeyPEM, csr.X509CertificateRequestPEM,
		x509.OverrideSubject(func(subject *pkix.Name) {
			subject.Organization = nil
		}),
	)
	require.NoError(t, err)

	assert.Equal(t, []string{"os:admin"}, crt1.X509Certificate.Subject.Organization)
	assert.Equal(t, []string(nil), crt2.X509Certificate.Subject.Organization)
}

func TestPEMEncodedCertificateAndKeyYAMLMarshaling(t *testing.T) {
	t.Parallel()

	// when key is not set to redacted, it should be base64'd on marshaling

	pair := &x509.PEMEncodedCertificateAndKey{
		Crt: []byte("crt"),
		Key: []byte("key"),
	}

	bytes, err := yaml.Marshal(pair)
	require.NoError(t, err)

	var m map[string]any

	require.NoError(t, yaml.Unmarshal(bytes, &m))

	assert.Equal(t, base64.StdEncoding.EncodeToString(pair.Key), m["key"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(pair.Crt), m["crt"])

	// when the key is set to Redacted, it should be marshaled as-is, without base64 encoding

	pair.Key = []byte(x509.Redacted)

	bytes, err = yaml.Marshal(pair)
	require.NoError(t, err)

	require.NoError(t, yaml.Unmarshal(bytes, &m))

	assert.Equal(t, x509.Redacted, m["key"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(pair.Crt), m["crt"])

	// unmarshal should work with redacted key

	var unmarshalPair x509.PEMEncodedCertificateAndKey

	require.NoError(t, yaml.Unmarshal(bytes, &unmarshalPair))

	assert.Equal(t, []byte(x509.Redacted), unmarshalPair.Key)
}

func TestPEMEncodedCertificate(t *testing.T) {
	t.Parallel()

	ca, err := x509.NewSelfSignedCertificateAuthority(x509.ECDSA(true))
	require.NoError(t, err)

	pemEncoded := &x509.PEMEncodedCertificate{
		Crt: ca.CrtPEM,
	}

	marshaled, err := yaml.Marshal(pemEncoded)
	require.NoError(t, err)

	var decoded x509.PEMEncodedCertificate

	require.NoError(t, yaml.Unmarshal(marshaled, &decoded))

	assert.Equal(t, ca.CrtPEM, decoded.Crt)

	decodedCert, err := decoded.GetCert()
	require.NoError(t, err)

	assert.True(t, decodedCert.Equal(ca.Crt))
}
