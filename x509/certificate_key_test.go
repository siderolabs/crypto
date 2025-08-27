// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/siderolabs/crypto/x509"
)

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

func TestNewCertificateAndKey(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string

		opts []x509.Option
	}{
		{
			name: "Ed25519",
			opts: nil,
		},
		{
			name: "RSA",
			opts: []x509.Option{
				x509.RSA(true),
			},
		},
		{
			name: "ECDSA",
			opts: []x509.Option{
				x509.ECDSA(true),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ca, err := x509.NewSelfSignedCertificateAuthority(test.opts...)
			require.NoError(t, err)

			pemEncoded := x509.NewCertificateAndKeyFromCertificateAuthority(ca)

			caCert, err := pemEncoded.GetCert()
			require.NoError(t, err)

			caKey, err := pemEncoded.GetKey()
			require.NoError(t, err)

			_, err = x509.NewCertificateAndKey(caCert, caKey)
			require.NoError(t, err)
		})
	}
}

func TestCertificateKeyPEMOpenSSLInterop(t *testing.T) {
	t.Parallel()

	_, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found, skipping test")
	}

	for _, test := range []struct { //nolint:govet
		name string

		opensslArgs     []string
		expectedKeyType any
	}{
		{
			name:        "RSA",
			opensslArgs: []string{"-x509", "-newkey", "rsa:2048"},

			expectedKeyType: &rsa.PrivateKey{},
		},
		{
			name: "Ed25519",

			opensslArgs:     []string{"-x509", "-newkey", "ed25519"},
			expectedKeyType: ed25519.PrivateKey(nil),
		},
		{
			name: "ECDSA",

			opensslArgs:     []string{"-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"},
			expectedKeyType: &ecdsa.PrivateKey{},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()

			// generate a new self-signed certificate and key
			output, err := exec.CommandContext(
				t.Context(),
				"openssl",
				slices.Concat(
					slices.Concat([]string{"req"}, test.opensslArgs),
					[]string{
						"-keyout", filepath.Join(tmpDir, "key.pem"), "-out", filepath.Join(tmpDir, "crt.pem"), "-days", "3650", "-nodes",
						"-subj", "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname",
					},
				)...,
			).CombinedOutput()
			require.NoError(t, err, string(output))

			crtAndKey, err := x509.NewCertificateAndKeyFromFiles(filepath.Join(tmpDir, "crt.pem"), filepath.Join(tmpDir, "key.pem"))
			require.NoError(t, err)

			_, err = crtAndKey.GetCert()
			require.NoError(t, err)

			k, err := crtAndKey.GetKey()
			require.NoError(t, err)

			require.IsType(t, test.expectedKeyType, k)

			ca, err := x509.NewCertificateAuthorityFromCertificateAndKey(crtAndKey)
			require.NoError(t, err)

			csr, _, err := x509.NewCSRAndIdentityFromCA(ca.Crt, x509.Organization("test"), x509.CommonName("myself"))
			require.NoError(t, err)

			_, err = x509.NewCertificateFromCSRBytes(ca.CrtPEM, ca.KeyPEM, csr.X509CertificateRequestPEM)
			require.NoError(t, err)
		})
	}
}
