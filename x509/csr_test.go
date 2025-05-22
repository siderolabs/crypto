// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/crypto/x509"
)

func TestNewCSRAndIdentityFromCA(t *testing.T) {
	t.Parallel()

	for _, test := range []struct { //nolint:govet
		name string

		opts []x509.Option

		expectedSignatureAlgorithm stdx509.SignatureAlgorithm
		expectedKeyType            any
	}{
		{
			name: "Ed25519",
			opts: nil,

			expectedSignatureAlgorithm: stdx509.PureEd25519,
			expectedKeyType:            ed25519.PrivateKey(nil),
		},
		{
			name: "RSA",
			opts: []x509.Option{
				x509.RSA(true),
			},

			expectedSignatureAlgorithm: stdx509.SHA512WithRSA,
			expectedKeyType:            &rsa.PrivateKey{},
		},
		{
			name: "ECDSA",
			opts: []x509.Option{
				x509.ECDSA(true),
			},

			expectedSignatureAlgorithm: stdx509.ECDSAWithSHA256,
			expectedKeyType:            &ecdsa.PrivateKey{},
		},
		{
			name: "ECDSA-SHA512",
			opts: []x509.Option{
				x509.ECDSASHA512(true),
			},

			expectedSignatureAlgorithm: stdx509.ECDSAWithSHA256,
			expectedKeyType:            &ecdsa.PrivateKey{},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ca, err := x509.NewSelfSignedCertificateAuthority(test.opts...)
			require.NoError(t, err)

			csr, identity, err := x509.NewCSRAndIdentityFromCA(ca.Crt, x509.Organization("test"), x509.CommonName("myself"))
			require.NoError(t, err)

			assert.Equal(t, test.expectedSignatureAlgorithm, csr.X509CertificateRequest.SignatureAlgorithm)

			key, err := identity.GetKey()
			require.NoError(t, err)

			assert.IsType(t, test.expectedKeyType, key)
		})
	}
}
