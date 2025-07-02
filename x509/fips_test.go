// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509_test

import (
	"crypto/fips140"
	"testing"
)

func TestFIPS(t *testing.T) {
	t.Logf("FIPS mode enabled: %v", fips140.Enabled())
}
