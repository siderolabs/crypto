// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/siderolabs/crypto/x509"
)

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
