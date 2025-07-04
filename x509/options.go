// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"time"
)

// Options is the functional options struct.
//
//nolint:govet
type Options struct {
	CommonName         string
	Organizations      []string
	SignatureAlgorithm x509.SignatureAlgorithm
	IPAddresses        []net.IP
	DNSNames           []string
	Bits               int
	NotAfter           time.Time
	NotBefore          time.Time
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage

	// Used with CSR signing process to override fields in the certificate subject.
	OverrideSubject func(*pkix.Name)
}

// Option is the functional option func.
type Option func(*Options)

// CommonName sets the common name of the certificate.
func CommonName(o string) Option {
	return func(opts *Options) {
		opts.CommonName = o
	}
}

// Organization sets the subject organizations of the certificate.
func Organization(o ...string) Option {
	return func(opts *Options) {
		opts.Organizations = o
	}
}

// SignatureAlgorithm sets the hash algorithm used to sign the SSL certificate.
func SignatureAlgorithm(o x509.SignatureAlgorithm) Option {
	return func(opts *Options) {
		opts.SignatureAlgorithm = o
	}
}

// IPAddresses sets the value for the IP addresses in Subject Alternate Name of
// the certificate.
func IPAddresses(o []net.IP) Option {
	return func(opts *Options) {
		opts.IPAddresses = o
	}
}

// DNSNames sets the value for the DNS Names in Subject Alternate Name of
// the certificate.
func DNSNames(o []string) Option {
	return func(opts *Options) {
		opts.DNSNames = o
	}
}

// Bits sets the bit size of the RSA key pair.
func Bits(o int) Option {
	return func(opts *Options) {
		opts.Bits = o
	}
}

// KeyUsage sets the bitmap of the KeyUsage* constants.
func KeyUsage(o x509.KeyUsage) Option {
	return func(opts *Options) {
		opts.KeyUsage = o
	}
}

// ExtKeyUsage sets the ExtKeyUsage* constants.
func ExtKeyUsage(o []x509.ExtKeyUsage) Option {
	return func(opts *Options) {
		opts.ExtKeyUsage = o
	}
}

// RSA sets a flag for indicating that the requested operation should be
// performed under the context of RSA-SHA512 instead of the default Ed25519.
func RSA(o bool) Option {
	return func(opts *Options) {
		if o {
			opts.SignatureAlgorithm = x509.SHA512WithRSA
		}
	}
}

// ECDSA sets a flag for indicating that the requested operation should be
// performed under the context of ECDSA instead of the default Ed25519.
func ECDSA(o bool) Option {
	return func(opts *Options) {
		if o {
			opts.SignatureAlgorithm = x509.ECDSAWithSHA256
		}
	}
}

// ECDSASHA512 sets a flag for indicating that the requested operation should be
// performed under the context of ECDSA with SHA512 instead of the default Ed25519.
//
// Note: this is only used for compatibility with previous version of the library,
// new code should always use ECDSA(true).
func ECDSASHA512(o bool) Option {
	return func(opts *Options) {
		if o {
			opts.SignatureAlgorithm = x509.ECDSAWithSHA512
		}
	}
}

// NotAfter sets the validity bound describing when a certificate expires.
func NotAfter(o time.Time) Option {
	return func(opts *Options) {
		opts.NotAfter = o
	}
}

// NotBefore sets the validity bound describing when a certificate becomes valid.
func NotBefore(o time.Time) Option {
	return func(opts *Options) {
		opts.NotBefore = o
	}
}

// OverrideSubject sets the option to override fields in the certificate subject when signing a CSR.
func OverrideSubject(f func(*pkix.Name)) Option {
	return func(opts *Options) {
		opts.OverrideSubject = f
	}
}

// WithCopyOptions copies the provided options to the Options struct.
func WithCopyOptions(opts *Options) Option {
	return func(o *Options) {
		*o = *opts // Copy the provided options into the current options
	}
}

// NewDefaultOptions initializes the Options struct with default values.
func NewDefaultOptions(setters ...Option) *Options {
	opts := &Options{
		SignatureAlgorithm: x509.PureEd25519,
		IPAddresses:        []net.IP{},
		DNSNames:           []string{},
		Bits:               4096,
		NotAfter:           time.Now().Add(DefaultCertificateValidityDuration),
		NotBefore:          time.Now(),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}
