// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
)

func TestKeyCheckIsDeterministicPerSalt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	salt := make([]byte, 16)
	a := keyCheckWithSalt(key, salt)
	b := keyCheckWithSalt(key, salt)
	if a != b {
		t.Fatal("same key and salt gave different check values")
	}
	if len(a.DigestHex) != 64 || a.SaltB64 != base64.RawURLEncoding.EncodeToString(salt) {
		t.Fatalf("bad check value %+v", a)
	}
	c := keyCheckWithSalt([]byte("another key, another check value"), salt)
	if c.DigestHex == a.DigestHex {
		t.Fatal("different keys gave the same check value")
	}
	fresh, err := NewKeyCheck(key)
	if err != nil || fresh.SaltB64 == a.SaltB64 {
		t.Fatalf("NewKeyCheck must draw a fresh salt: %+v %v", fresh, err)
	}
}

func TestIsUnsupported(t *testing.T) {
	if !IsUnsupported(fmt.Errorf("renew: %w", ErrUnsupported)) {
		t.Fatal("a wrapped ErrUnsupported must be unsupported")
	}
	if IsUnsupported(errors.New("other")) {
		t.Fatal("another error is not unsupported")
	}
}
