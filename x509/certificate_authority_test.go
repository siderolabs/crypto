// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	stdx509 "crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/crypto/x509"
)

func TestNewCertificateAuthority(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string

		opts []x509.Option

		expectedPublicKeyAlgorithm stdx509.PublicKeyAlgorithm
		expectedSignatureAlgorithm stdx509.SignatureAlgorithm
	}{
		{
			name: "Ed25519",
			opts: nil,

			expectedPublicKeyAlgorithm: stdx509.Ed25519,
			expectedSignatureAlgorithm: stdx509.PureEd25519,
		},
		{
			name: "RSA",
			opts: []x509.Option{
				x509.RSA(true),
			},

			expectedPublicKeyAlgorithm: stdx509.RSA,
			expectedSignatureAlgorithm: stdx509.SHA512WithRSA,
		},
		{
			name: "ECDSA",
			opts: []x509.Option{
				x509.ECDSA(true),
			},

			expectedPublicKeyAlgorithm: stdx509.ECDSA,
			expectedSignatureAlgorithm: stdx509.ECDSAWithSHA256,
		},
		{
			name: "ECDSA-SHA512",
			opts: []x509.Option{
				x509.ECDSASHA512(true),
			},

			expectedPublicKeyAlgorithm: stdx509.ECDSA,
			expectedSignatureAlgorithm: stdx509.ECDSAWithSHA512,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ca, err := x509.NewSelfSignedCertificateAuthority(test.opts...)
			require.NoError(t, err)

			assert.Equal(t, test.expectedPublicKeyAlgorithm, ca.Crt.PublicKeyAlgorithm)
			assert.Equal(t, test.expectedSignatureAlgorithm, ca.Crt.SignatureAlgorithm)
		})
	}
}
