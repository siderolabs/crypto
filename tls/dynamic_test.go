// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tls_test

import (
	"context"
	stdx509 "crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"

	"github.com/siderolabs/crypto/tls"
	"github.com/siderolabs/crypto/x509"
)

func TestDynamicCertificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ca, err := x509.NewSelfSignedCertificateAuthority()
	require.NoError(t, err)

	serverIdentity, err := x509.NewKeyPair(ca,
		x509.Organization("test"),
		x509.CommonName("server"),
		x509.ExtKeyUsage([]stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}),
	)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	require.NoError(t, os.WriteFile(certPath, serverIdentity.CrtPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, serverIdentity.KeyPEM, 0o600))

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	logger := zaptest.NewLogger(t)

	eg, ctx := errgroup.WithContext(ctx)

	t.Cleanup(func() {
		cancel()
		require.NoError(t, eg.Wait())
	})

	dynamic := tls.NewDynamicCertificate(certPath, keyPath)
	require.NoError(t, dynamic.Load())

	eg.Go(func() error {
		return dynamic.WatchWithRestarts(ctx, logger)
	})

	cert, err := dynamic.GetCertificate(nil)
	require.NoError(t, err)

	assert.Equal(t, "server", cert.Leaf.Subject.CommonName)

	// issue new cert
	serverIdentity, err = x509.NewKeyPair(ca,
		x509.Organization("test"),
		x509.CommonName("server-new"),
		x509.ExtKeyUsage([]stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}),
	)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(certPath, serverIdentity.CrtPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, serverIdentity.KeyPEM, 0o600))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		asrt := assert.New(c)

		cert, err = dynamic.GetCertificate(nil)
		require.NoError(c, err)

		asrt.Equal("server-new", cert.Leaf.Subject.CommonName)
	}, 5*time.Second, 100*time.Millisecond)
}
