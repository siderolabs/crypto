// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package tls provides tls.Config generation and certificate management.
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// Type represents the TLS authentication type.
type Type int

const (
	// Mutual configures the server's policy for TLS Client Authentication to
	// mutual TLS.
	Mutual Type = 1 << iota
	// ServerOnly configures the server's policy for TLS Client Authentication
	// to server only.
	ServerOnly
)

// ConfigOptionFunc describes a configuration option function for the TLS config.
type ConfigOptionFunc func(*tls.Config) error

// WithClientAuthType declares the server's policy regardling TLS Client Authentication.
func WithClientAuthType(t Type) func(*tls.Config) error {
	return func(cfg *tls.Config) error {
		switch t {
		case Mutual:
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		case ServerOnly:
			cfg.ClientAuth = tls.NoClientCert
		default:
			return fmt.Errorf("unhandled client auth type %+v", t)
		}

		return nil
	}
}

// WithServerCertificateProvider declares a dynamic provider for the server
// certificate.
//
// NOTE: specifying this option will CLEAR any configured Certificates, since
// they would otherwise override this option.
func WithServerCertificateProvider(p CertificateProvider) func(*tls.Config) error {
	return func(cfg *tls.Config) error {
		if p == nil {
			return errors.New("no provider")
		}

		cfg.Certificates = nil
		cfg.GetCertificate = p.GetCertificate

		return nil
	}
}

// WithClientCertificateProvider declares a dynamic provider for the client
// certificate.
//
// NOTE: specifying this option will CLEAR any configured Certificates, since
// they would otherwise override this option.
func WithClientCertificateProvider(p CertificateProvider) func(*tls.Config) error {
	return func(cfg *tls.Config) error {
		if p == nil {
			return errors.New("no provider")
		}

		cfg.Certificates = nil
		cfg.GetClientCertificate = p.GetClientCertificate

		return nil
	}
}

// WithKeypair declares a specific TLS keypair to be used.  This can be called
// multiple times to add additional keypairs.
func WithKeypair(cert tls.Certificate) func(*tls.Config) error {
	return func(cfg *tls.Config) error {
		cfg.Certificates = append(cfg.Certificates, cert)

		return nil
	}
}

// WithCACertPEM declares a PEM-encoded CA Certificate to be used.
func WithCACertPEM(ca []byte) func(*tls.Config) error {
	return func(cfg *tls.Config) error {
		if len(ca) == 0 {
			return errors.New("no CA cert provided")
		}

		if ok := cfg.ClientCAs.AppendCertsFromPEM(ca); !ok {
			return errors.New("failed to append CA certificate to ClientCAs pool")
		}

		if ok := cfg.RootCAs.AppendCertsFromPEM(ca); !ok {
			return errors.New("failed to append CA certificate to RootCAs pool")
		}

		return nil
	}
}

// WithDynamicClientCA declares a dynamic client CA which will be updated on each client request.
//
// This methods is for server-side TLS.
// For client TLS, build the new `tls.Config` on each request.
func WithDynamicClientCA(p CertificateProvider) func(*tls.Config) error {
	return func(cfg *tls.Config) error {
		cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			newCfg := cfg.Clone()

			var err error

			newCfg.ClientCAs, err = p.GetCACertPool()
			if err != nil {
				return nil, err
			}

			return newCfg, nil
		}

		return nil
	}
}

// WithMinVersion sets the minimum TLS version to use.
func WithMinVersion(version uint16) func(*tls.Config) error {
	return func(cfg *tls.Config) error {
		cfg.MinVersion = version

		return nil
	}
}

func defaultConfig() *tls.Config {
	return &tls.Config{
		RootCAs:                x509.NewCertPool(),
		ClientCAs:              x509.NewCertPool(),
		SessionTicketsDisabled: true,
		// TLS 1.2
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	}
}

// New returns a new TLS Configuration modified by any provided configuration options.
func New(opts ...ConfigOptionFunc) (*tls.Config, error) {
	cfg := defaultConfig()

	for _, f := range opts {
		if err := f(cfg); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}
