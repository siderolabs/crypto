// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/crypto/x509"
)

var (
	testEKU = asn1.ObjectIdentifier{2, 25, 1, 2, 3, 4}
	testURI = &url.URL{Scheme: "spiffe", Host: "example.com", Path: "/service"}

	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

func TestNewKeyPairExtensions(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		opt  x509.Option
		name string
	}{
		{
			name: "RSA",
			opt:  x509.RSA(true),
		},
		{
			name: "Ed25519",
			opt:  x509.RSA(false),
		},
		{
			name: "ECDSA",
			opt:  x509.ECDSA(true),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca, err := x509.NewSelfSignedCertificateAuthority(tt.opt)
			require.NoError(t, err)

			keyPair, err := x509.NewKeyPair(ca,
				x509.IPAddresses([]net.IP{net.ParseIP("10.5.0.2")}),
				x509.DNSNames([]string{"example.com"}),
				x509.CommonName("example.com"),
				x509.KeyUsage(stdx509.KeyUsageDigitalSignature),
				x509.ExtKeyUsage([]stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}),
				x509.UnknownExtKeyUsage([]asn1.ObjectIdentifier{testEKU}),
				x509.URIs([]*url.URL{testURI}),
			)
			require.NoError(t, err)

			crt, err := stdx509.ParseCertificate(keyPair.Certificate.Certificate[0])
			require.NoError(t, err)

			assert.Equal(t, []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}, crt.ExtKeyUsage)
			assert.Equal(t, []asn1.ObjectIdentifier{testEKU}, crt.UnknownExtKeyUsage)
			assert.Equal(t, []string{testURI.String()}, urisToStrings(crt.URIs))
			assert.Equal(t, []string{"example.com"}, crt.DNSNames)
			assert.True(t, crt.IPAddresses[0].Equal(net.ParseIP("10.5.0.2")))

			// the certificate should still be accepted as a regular server certificate:
			// the CA has EKUs set, and custom EKU on the leaf should not break verification
			roots := stdx509.NewCertPool()
			roots.AddCert(ca.Crt)

			for _, name := range []string{"example.com", "10.5.0.2"} {
				_, err = crt.Verify(stdx509.VerifyOptions{
					DNSName:   name,
					Roots:     roots,
					KeyUsages: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
				})
				require.NoError(t, err, name)
			}
		})
	}
}

func TestNewKeyPairNoExtensions(t *testing.T) {
	t.Parallel()

	ca, err := x509.NewSelfSignedCertificateAuthority(x509.ECDSA(true))
	require.NoError(t, err)

	keyPair, err := x509.NewKeyPair(ca)
	require.NoError(t, err)

	crt, err := stdx509.ParseCertificate(keyPair.Certificate.Certificate[0])
	require.NoError(t, err)

	assert.Empty(t, crt.UnknownExtKeyUsage)
	assert.Empty(t, crt.URIs)
	assert.Equal(t, []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth, stdx509.ExtKeyUsageClientAuth}, crt.ExtKeyUsage)
}

func TestCSRWithURIs(t *testing.T) {
	t.Parallel()

	csr, _, err := x509.NewECDSACSRAndIdentity(x509.URIs([]*url.URL{testURI}))
	require.NoError(t, err)

	block, _ := pem.Decode(csr.X509CertificateRequestPEM)
	require.NotNil(t, block)

	parsed, err := stdx509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	assert.Equal(t, []string{testURI.String()}, urisToStrings(parsed.URIs))
}

// TestNewCertificateFromCSRIgnoresRequestedExtensions verifies that a CSR can't be used to
// request URIs or extended key usages: these are controlled only by the signer.
func TestNewCertificateFromCSRIgnoresRequestedExtensions(t *testing.T) {
	t.Parallel()

	ca, err := x509.NewSelfSignedCertificateAuthority(x509.ECDSA(true))
	require.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ekuExtension, err := asn1.Marshal([]asn1.ObjectIdentifier{
		testEKU,
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // client auth
	})
	require.NoError(t, err)

	// craft a hostile CSR requesting URIs and custom EKU
	csrDER, err := stdx509.CreateCertificateRequest(rand.Reader, &stdx509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "attacker"},
		DNSNames: []string{"example.com"},
		URIs:     []*url.URL{testURI},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    oidExtensionExtendedKeyUsage,
				Value: ekuExtension,
			},
		},
	}, privKey)
	require.NoError(t, err)

	csr, err := stdx509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	require.Equal(t, []string{testURI.String()}, urisToStrings(csr.URIs))

	t.Run("signer options not set", func(t *testing.T) {
		t.Parallel()

		crt, err := x509.NewCertificateFromCSR(ca.Crt, ca.Key, csr,
			x509.ExtKeyUsage([]stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}),
		)
		require.NoError(t, err)

		assert.Equal(t, "attacker", crt.X509Certificate.Subject.CommonName)
		assert.Equal(t, []string{"example.com"}, crt.X509Certificate.DNSNames)
		assert.Empty(t, crt.X509Certificate.URIs)
		assert.Empty(t, crt.X509Certificate.UnknownExtKeyUsage)
		assert.Equal(t, []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}, crt.X509Certificate.ExtKeyUsage)
	})

	t.Run("signer options set", func(t *testing.T) {
		t.Parallel()

		signerURI := &url.URL{Scheme: "spiffe", Host: "example.com", Path: "/other"}
		signerEKU := asn1.ObjectIdentifier{2, 25, 5, 6, 7, 8}

		crt, err := x509.NewCertificateFromCSR(ca.Crt, ca.Key, csr,
			x509.ExtKeyUsage([]stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}),
			x509.UnknownExtKeyUsage([]asn1.ObjectIdentifier{signerEKU}),
			x509.URIs([]*url.URL{signerURI}),
		)
		require.NoError(t, err)

		assert.Equal(t, []string{signerURI.String()}, urisToStrings(crt.X509Certificate.URIs))
		assert.Equal(t, []asn1.ObjectIdentifier{signerEKU}, crt.X509Certificate.UnknownExtKeyUsage)
		assert.Equal(t, []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}, crt.X509Certificate.ExtKeyUsage)
	})
}

func urisToStrings(uris []*url.URL) []string {
	result := make([]string, 0, len(uris))

	for _, u := range uris {
		result = append(result, u.String())
	}

	return result
}
