// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//nolint: scopelint
package x509_test

import (
	"testing"

	"github.com/talos-systems/crypto/x509"
)

func TestNewKeyPair(t *testing.T) {
	rsaCA, err := x509.NewSelfSignedCertificateAuthority(x509.RSA(true))
	if err != nil {
		t.Fatal(err)
	}

	ed25519ca, err := x509.NewSelfSignedCertificateAuthority(x509.RSA(false))
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ca      *x509.CertificateAuthority
		setters []x509.Option
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid RSA",
			args: args{
				ca:      rsaCA,
				setters: []x509.Option{x509.RSA(true)},
			},
			wantErr: false,
		},
		{
			name: "valid Ed25519",
			args: args{
				ca:      ed25519ca,
				setters: []x509.Option{x509.RSA(false)},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := x509.NewKeyPair(tt.args.ca, tt.args.setters...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKeyPair() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
		})
	}
}
