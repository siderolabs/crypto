// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	"encoding/base64"
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
