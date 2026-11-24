// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The vault's own update_policy_from vector (formats §5.3).
func TestUpdatePolicyFromVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		From struct {
			CurrentPD     string `json:"current_pd"`
			CurrentPolicy string `json:"current_policy_as_get_policy_returns_it"`
			NewPD         string `json:"new_pd"`
			Target        string
			Text          string
			VaultOp       string `json:"vault_op"`
		} `json:"binding_v2_update_policy_from"`
		Policy struct {
			PD string `json:"pd"`
		} `json:"policy_digest"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	f := v.From
	if pd, err := PolicyDigestJSON([]byte(f.CurrentPolicy)); err != nil || pd != f.CurrentPD {
		t.Fatalf("PD(current) = %s (%v), want %s", pd, err, f.CurrentPD)
	}
	if f.NewPD != v.Policy.PD {
		t.Fatalf("new_pd %s is not the policy_digest vector's %s", f.NewPD, v.Policy.PD)
	}
	target, err := UpdatePolicyFromTarget(f.CurrentPD, f.NewPD)
	if err != nil || target != f.Target {
		t.Fatalf("target %s (%v), want %s", target, err, f.Target)
	}
	// Rebuild the binding from the fields of its text and compare both.
	lines := strings.Split(f.Text, "\n")
	n, _ := strconv.Atoi(lines[1])
	rest := lines[2+n:]
	if len(rest) != 8 {
		t.Fatalf("text has %d fields after the members", len(rest))
	}
	pv, _ := strconv.ParseUint(rest[3], 10, 64)
	exp, _ := strconv.ParseInt(rest[7], 10, 64)
	b := BindingV2{Members: lines[2 : 2+n], Op: BindUpdatePolicyFrom, Handle: rest[1], Target: target,
		PolicyVersion: pv, Approver: rest[4], HolderHead: rest[5], Nonce: rest[6], Exp: exp}
	if rest[0] != string(BindUpdatePolicyFrom) {
		t.Fatalf("op %q", rest[0])
	}
	text, err := b.Text()
	if err != nil || text != f.Text {
		t.Fatalf("text:\n got %q (%v)\nwant %q", text, err, f.Text)
	}
	if op, err := b.VaultOp(); err != nil || op != f.VaultOp {
		t.Fatalf("vault_op %s (%v), want %s", op, err, f.VaultOp)
	}
}

func TestUpdatePolicyFromTargetRefusesBadDigests(t *testing.T) {
	good := strings.Repeat("a", 64)
	for _, bad := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		if _, err := UpdatePolicyFromTarget(bad, good); err == nil {
			t.Errorf("current %q accepted", bad)
		}
		if _, err := UpdatePolicyFromTarget(good, bad); err == nil {
			t.Errorf("new %q accepted", bad)
		}
	}
}

func TestUpdatePolicyRawFromSendsReplacedPD(t *testing.T) {
	policy := json.RawMessage(`{"operations":[]}`)
	pd := strings.Repeat("c", 64)
	c := &Client{opts: DialOptions{BindingMembers: []string{memberA}}}
	raw, err := c.updatePolicyRawFromPayload("h", policy, pd, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"UpdatePolicy":{"handle":"h","new_policy":{"operations":[]},"binding":{"members":["` + memberA + `"],"replaced_pd":"` + pd + `"}}}`
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}
	// Without a member set there is no binding v2 to carry it.
	if _, err := (&Client{}).updatePolicyRawFromPayload("h", policy, pd, nil); err == nil {
		t.Fatal("update_policy_from without members was built")
	}
}
