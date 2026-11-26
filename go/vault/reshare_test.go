// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A clean-up that failed on some vaults names exactly those vaults, keeps
// every vault's error, and is found with errors.As through a wrapper.
func TestReshareCleanupNamesTheVaultsStillHoldingShares(t *testing.T) {
	denied := &ErrVaultError{Message: "no OperationRule grants DeleteKey to caller with all conditions met: OidcStepUp: binding v2 required: the request must name its members"}
	eps := []string{"a:1", "b:2", "c:3"}
	got := collectCleanup(eps, false, func(i int, ep string) error {
		switch ep {
		case "a:1":
			return fmt.Errorf("dial: %w", errors.New("connection refused"))
		case "c:3":
			return denied
		}
		return nil
	})
	if got == nil {
		t.Fatal("expected a clean-up error")
	}
	if strings.Join(got.Vaults, ",") != "a:1,c:3" || got.InPlace {
		t.Fatalf("vaults = %v, in place = %v", got.Vaults, got.InPlace)
	}
	var wrapped error = fmt.Errorf("renew: %w", got)
	var ce *ReshareCleanupError
	if !errors.As(wrapped, &ce) || ce != got {
		t.Fatal("errors.As does not find the clean-up error")
	}
	var ve *ErrVaultError
	if !errors.As(wrapped, &ve) || ve != denied {
		t.Fatal("the vault's own refusal is not reachable")
	}
	msg := got.Error()
	for _, want := range []string{"reshared", "a:1", "c:3", "connection refused", "binding v2 required"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "b:2") {
		t.Fatalf("message %q names a vault that was cleaned up", msg)
	}
}

func TestReshareCleanupNilWhenEveryVaultIsClean(t *testing.T) {
	calls := 0
	got := collectCleanup([]string{"a:1", "b:2"}, true, func(int, string) error { calls++; return nil })
	if got != nil || calls != 2 {
		t.Fatalf("got %v after %d calls", got, calls)
	}
}

// A finalize is the vault's FrostReshareFinalize request for the handle.
func TestFinalizeReshareEncodes(t *testing.T) {
	raw, err := json.Marshal(vaultRequest{FrostReshareFinalize: &handleReq{Handle: "h"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"FrostReshareFinalize":{"handle":"h"}}` {
		t.Fatalf("got %s", raw)
	}
}
