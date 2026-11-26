// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestIsKeyDeleted(t *testing.T) {
	deleted := &ErrVaultError{Message: "key deleted at 1764000000 (delete); successor -; the handle is reusable after 1771776000"}
	if !IsKeyDeleted(deleted) || !IsKeyDeleted(fmt.Errorf("wrapped: %w", deleted)) {
		t.Fatal("a deleted key's error not recognised")
	}
	if !IsKeyDeleted(&ErrKeyDeleted{}) {
		t.Fatal("ErrKeyDeleted not recognised")
	}
	for _, msg := range []string{"key not found", "caller is not in policy.principals", "the successor has been deleted"} {
		if IsKeyDeleted(&ErrVaultError{Message: msg}) {
			t.Fatalf("%q read as deleted", msg)
		}
	}
	if !IsHandleTombstoned(&ErrVaultError{Message: "handle deleted at 1; reusable after 2: choose another name"}) {
		t.Fatal("a tombstoned create not recognised")
	}
}

func TestGetKeyInfoDecodesATombstone(t *testing.T) {
	var resp vaultResponse
	raw := `{"KeyTombstone":{"handle":"users/a/k","key_type":"RawShare","op":"delete_after","deleted_at":5,"successor":"users/a/k/gen-2","expires_at":9}}`
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.KeyTombstone == nil || resp.KeyTombstone.Successor != "users/a/k/gen-2" || resp.KeyTombstone.ExpiresAt != 9 {
		t.Fatalf("got %+v", resp.KeyTombstone)
	}
	var ki KeyInfo
	if err := json.Unmarshal([]byte(`{"handle":"h","key_type":"RawShare","exportable":true,"created_at":1,"expires_at":2,"policy_version":1,"created_by_owner_approval":true}`), &ki); err != nil {
		t.Fatal(err)
	}
	if !ki.CreatedByOwnerApproval {
		t.Fatal("created_by_owner_approval not decoded")
	}
}

func TestReCreatedNames(t *testing.T) {
	for h, want := range map[string]bool{
		"vaults/v/k/new-2":       true,
		"vaults/v/k/new-12":      true,
		"vaults/v/k":             false,
		"vaults/v/k/new-":        false,
		"vaults/v/k/new-2x":      false,
		"vaults/v/k/new-2/gen-3": false,
	} {
		if IsReCreatedName(h) != want {
			t.Fatalf("IsReCreatedName(%q) != %v", h, want)
		}
	}
	if !IsBeneathReCreatedName("vaults/v/k/new-2/gen-3") || IsBeneathReCreatedName("vaults/v/k/new-2") {
		t.Fatal("beneath")
	}
	if h, err := ReCreatedName("vaults/v/k", 3); err != nil || h != "vaults/v/k/new-3" {
		t.Fatal(h, err)
	}
	if _, err := ReCreatedName("vaults/v/k", 1); err == nil {
		t.Fatal("new-1 accepted")
	}
}

// A creation names its members only for a re-created name; other creations
// are sent exactly as before.
func TestCreateCarriesTheBindingOnlyForAReCreatedName(t *testing.T) {
	c := &Client{opts: DialOptions{BindingMembers: []string{memberA}}}
	raw, _ := json.Marshal(vaultRequest{CreateKey: &createKeyReq{Handle: "vaults/v/k/new-2", Grant: "g", Binding: c.createBinding("vaults/v/k/new-2")}})
	if !strings.Contains(string(raw), `"binding":{"members":["`+memberA+`"]}`) {
		t.Fatalf("no binding: %s", raw)
	}
	raw, _ = json.Marshal(vaultRequest{CreateKey: &createKeyReq{Handle: "vaults/v/k/v2", Grant: "g", Binding: c.createBinding("vaults/v/k/v2")}})
	if strings.Contains(string(raw), "binding") {
		t.Fatalf("binding sent for an ordinary create: %s", raw)
	}
	raw, _ = json.Marshal(vaultRequest{FrostDkgAbort: &frostSessionReq{Session: "s"}})
	if string(raw) != `{"FrostDkgAbort":{"session":"s"}}` {
		t.Fatalf("an abort without a handle changed: %s", raw)
	}
}
