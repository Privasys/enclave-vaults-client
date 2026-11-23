// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"encoding/json"
	"strings"
	"testing"
)

// The requests encode the way the vault's serde types decode them: an
// externally tagged variant, base64url (no padding) strings, and maps keyed
// by participant index as JSON object keys.
func TestFrostRequestsEncodeForTheVault(t *testing.T) {
	b, err := json.Marshal(vaultRequest{FrostDkgRound2: &frostDkgRound2Req{
		Session: "s", Handle: "h",
		Round1: map[uint16]frostRound1Message{1: {PackageB64: b64([]byte{1}), DhPublicB64: "Ag", QuoteB64: "Aw"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"FrostDkgRound2":{"session":"s","handle":"h","round1":{"1":{"package_b64":"AQ","dh_public_b64":"Ag","quote_b64":"Aw"}}}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	b, _ = json.Marshal(vaultRequest{FrostSignRound2: &frostSignRound2Req{
		Session: "s", Handle: "h", CommitmentsB64: b64Map(map[uint16][]byte{2: {0xff}}),
	}})
	if !strings.Contains(string(b), `"commitments_b64":{"2":"_w"}`) {
		t.Fatalf("got %s", b)
	}
}

// The responses decode what serde writes: byte vectors as arrays of numbers,
// maps keyed by index, unit variants as bare strings.
func TestFrostResponsesDecodeFromTheVault(t *testing.T) {
	r, err := unmarshalResponse([]byte(`{"FrostDkgSealed":{"packages":{"2":[1,2,3],"3":[4]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.FrostDkgSealed.Packages[2]; len(got) != 3 || got[2] != 3 {
		t.Fatalf("packages = %v", r.FrostDkgSealed.Packages)
	}
	r, err = unmarshalResponse([]byte(`{"FrostCommitment":{"index":2,"commitment":[9,8]}}`))
	if err != nil || r.FrostCommitment.Index != 2 || r.FrostCommitment.Commitment[1] != 8 {
		t.Fatalf("commitment = %+v, %v", r.FrostCommitment, err)
	}
	r, err = unmarshalResponse([]byte(`"FrostDone"`))
	if err != nil || r.FrostDone == nil {
		t.Fatalf("FrostDone = %+v, %v", r, err)
	}
	r, err = unmarshalResponse([]byte(`{"ThresholdKeyCreated":{"handle":"h","index":1,"threshold":2,"public_key":[7],"expires_at":42}}`))
	if err != nil || r.ThresholdKeyCreated.ExpiresAt != 42 || r.ThresholdKeyCreated.PublicKey[0] != 7 {
		t.Fatalf("created = %+v, %v", r.ThresholdKeyCreated, err)
	}
}
