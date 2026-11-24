// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

func TestBindingV2RuleJSON(t *testing.T) {
	c := Condition{OidcStepUp: &OidcStepUpCond{
		RequiredAmr: []string{"webauthn"}, OperationBound: true, FreshForSeconds: 300, Binding: 2,
	}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}`
	if string(b) != want {
		t.Fatalf("got %s\nwant %s", b, want)
	}
	var back Condition
	if err := json.Unmarshal([]byte(want), &back); err != nil || back.OidcStepUp == nil || back.OidcStepUp.Binding != 2 {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	// A v1 rule leaves the field out, as every key created before v2.
	v1, _ := json.Marshal(Condition{OidcStepUp: &OidcStepUpCond{RequiredAmr: []string{"webauthn"}, OperationBound: true}})
	if strings.Contains(string(v1), "binding") {
		t.Fatalf("a v1 rule must not carry binding: %s", v1)
	}
	p, _ := json.Marshal(KeyPolicy{Approval: "none"})
	if !strings.Contains(string(p), `"approval":"none"`) {
		t.Fatalf("approval none missing: %s", p)
	}
	q, _ := json.Marshal(KeyPolicy{})
	if strings.Contains(string(q), "approval") {
		t.Fatalf("an ordinary policy must not carry approval: %s", q)
	}
}
