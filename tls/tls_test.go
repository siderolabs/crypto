// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tls_test

import (
	"crypto/fips140"
	stdlibtls "crypto/tls"
	stdx509 "crypto/x509"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/crypto/tls"
	"github.com/siderolabs/crypto/x509"
)

type mockProvider struct {
	crt *stdlibtls.Certificate
}

// GetCA implements tls.CertificateProvider interface.
func (mockProvider) GetCA() ([]byte, error) {
	return nil, nil
}

// GetCACertPool implements tls.CertificateProvider interface.
func (mockProvider) GetCACertPool() (*stdx509.CertPool, error) {
	return nil, nil //nolint:nilnil
}

// GetCertificate implements tls.CertificateProvider interface.
func (m mockProvider) GetCertificate(*stdlibtls.ClientHelloInfo) (*stdlibtls.Certificate, error) {
	return m.crt, nil
}

// GetClientCertificate implements tls.CertificateProvider interface.
func (m mockProvider) GetClientCertificate(*stdlibtls.CertificateRequestInfo) (*stdlibtls.Certificate, error) {
	return m.crt, nil
}

func TestClientServer(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string

		opts     []x509.Option
		skipFIPS bool
	}{
		{
			name: "Ed25519", // Go 1.25 with FIPS-140-3 strict allows Ed25519
		},
		{
			name: "RSA",
			opts: []x509.Option{
				x509.RSA(true),
				x509.Bits(2048),
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

			if test.skipFIPS && fips140.Enabled() {
				t.Skip("Skipping test in FIPS mode")
			}

			ca, err := x509.NewSelfSignedCertificateAuthority(test.opts...)
			require.NoError(t, err)

			clientIdentity, err := x509.NewKeyPair(ca,
				x509.Organization("test"),
				x509.CommonName("client"),
				x509.ExtKeyUsage([]stdx509.ExtKeyUsage{stdx509.ExtKeyUsageClientAuth}),
			)
			require.NoError(t, err)

			serverIdentity, err := x509.NewKeyPair(ca,
				x509.Organization("test"),
				x509.CommonName("server"),
				x509.IPAddresses([]net.IP{net.ParseIP("127.0.0.1")}),
				x509.ExtKeyUsage([]stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}),
			)
			require.NoError(t, err)

			for _, interaction := range []struct { //nolint:govet
				name string

				srvTLSConfig    func() *stdlibtls.Config
				clientTLSConfig func() *stdlibtls.Config
			}{
				{
					name: "Mutual",
					srvTLSConfig: func() *stdlibtls.Config {
						srvTLSConfig, err := tls.New(
							tls.WithClientAuthType(tls.Mutual),
							tls.WithServerCertificateProvider(mockProvider{serverIdentity.Certificate}),
							tls.WithCACertPEM(ca.CrtPEM),
						)
						require.NoError(t, err)

						return srvTLSConfig
					},
					clientTLSConfig: func() *stdlibtls.Config {
						clientTLSConfig, err := tls.New(
							tls.WithClientAuthType(tls.Mutual),
							tls.WithClientCertificateProvider(mockProvider{clientIdentity.Certificate}),
							tls.WithCACertPEM(ca.CrtPEM),
						)
						require.NoError(t, err)

						return clientTLSConfig
					},
				},
				{
					name: "SrvOnly",
					srvTLSConfig: func() *stdlibtls.Config {
						srvTLSConfig, err := tls.New(
							tls.WithClientAuthType(tls.ServerOnly),
							tls.WithServerCertificateProvider(mockProvider{serverIdentity.Certificate}),
							tls.WithCACertPEM(ca.CrtPEM),
						)
						require.NoError(t, err)

						return srvTLSConfig
					},
					clientTLSConfig: func() *stdlibtls.Config {
						return &stdlibtls.Config{
							InsecureSkipVerify: true,
						}
					},
				},
			} {
				t.Run(interaction.name, func(t *testing.T) {
					t.Parallel()

					srvTLSConfig := interaction.srvTLSConfig()
					clientTLSConfig := interaction.clientTLSConfig()

					listener, err := stdlibtls.Listen("tcp", "localhost:0", srvTLSConfig)
					require.NoError(t, err)

					t.Cleanup(func() {
						require.NoError(t, listener.Close())
					})

					var wg sync.WaitGroup

					wg.Add(1)

					go func() {
						defer wg.Done()

						c, aerr := listener.Accept()
						require.NoError(t, aerr)

						if aerr != nil {
							return
						}

						t.Logf("Accepted connection from %s", c.RemoteAddr())

						_, aerr = c.Write([]byte("Hello, TLS client!"))
						require.NoError(t, aerr)

						if aerr != nil {
							return
						}

						require.NoError(t, c.Close())
					}()

					conn, err := (&stdlibtls.Dialer{
						Config: clientTLSConfig,
					}).DialContext(t.Context(), "tcp", listener.Addr().String())
					require.NoError(t, err)

					t.Logf("Connected to server at %s", conn.RemoteAddr())

					out, err := io.ReadAll(conn)
					require.NoError(t, err)

					t.Logf("Received from server: %s", out)

					require.Equal(t, "Hello, TLS client!", string(out))

					t.Cleanup(func() {
						require.NoError(t, conn.Close())
					})

					wg.Wait()
				})
			}
		})
	}
}
