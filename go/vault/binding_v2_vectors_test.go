// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// testdata/v2_vectors.json is the vault's own output (enclave-os-vault
// testdata/v2_vectors.json, which a vault test asserts its code produces).
func TestV2VectorsFromTheVault(t *testing.T) {
	raw, err := os.ReadFile("testdata/v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Billing struct {
			Issuer, Audience string
			BillingID        string `json:"billing_id"`
		} `json:"billing_id_implicit_v0"`
		Binding struct {
			Approver, Handle, Nonce, Op, Target, Text string
			Exp                                       int64
			HolderHead                                string `json:"holder_head"`
			Members                                   []string
			PolicyVersion                             uint64 `json:"policy_version"`
			VaultOp                                   string `json:"vault_op"`
		} `json:"binding_v2_update_policy_with_pd"`
		Identity struct {
			BillingID string `json:"billing_id"`
			MemberID  string `json:"member_id"`
			RD        string `json:"report_data_first_32_hex"`
		} `json:"identity_report_data"`
		Member struct {
			MemberID string `json:"member_id"`
			Pub      string `json:"public_key_sec1_hex"`
		} `json:"member_id"`
		Policy struct {
			JCS          string `json:"jcs"`
			PD           string `json:"pd"`
			PolicyAsSent string `json:"policy_as_sent"`
		} `json:"policy_digest"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	jcs, err := CanonicalJSON([]byte(v.Policy.PolicyAsSent))
	if err != nil {
		t.Fatal(err)
	}
	if string(jcs) != v.Policy.JCS {
		t.Errorf("JCS:\n got %s\nwant %s", jcs, v.Policy.JCS)
	}
	if pd, err := PolicyDigestJSON([]byte(v.Policy.PolicyAsSent)); err != nil || pd != v.Policy.PD {
		t.Errorf("PD %s (%v), want %s", pd, err, v.Policy.PD)
	}

	pub, _ := hex.DecodeString(v.Member.Pub)
	if mid, err := MemberID(pub); err != nil || mid != v.Member.MemberID {
		t.Errorf("member_id %s (%v), want %s", mid, err, v.Member.MemberID)
	}

	if rd := IdentityReportData(v.Identity.MemberID, v.Identity.BillingID); hex.EncodeToString(rd[:]) != v.Identity.RD {
		t.Errorf("identity report data %x, want %s", rd, v.Identity.RD)
	}
	if got := ImplicitBillingID(v.Billing.Issuer, v.Billing.Audience); got != v.Billing.BillingID {
		t.Errorf("implicit billing id %s, want %s", got, v.Billing.BillingID)
	}

	b := BindingV2{Members: v.Binding.Members, Op: BindingOp(v.Binding.Op), Handle: v.Binding.Handle,
		Target: v.Binding.Target, PolicyVersion: v.Binding.PolicyVersion, Approver: v.Binding.Approver,
		Nonce: v.Binding.Nonce, Exp: v.Binding.Exp}
	if v.Binding.HolderHead != "-" {
		b.HolderHead = v.Binding.HolderHead
	}
	if text, err := b.Text(); err != nil || text != v.Binding.Text {
		t.Errorf("binding text (%v):\n got %q\nwant %q", err, text, v.Binding.Text)
	}
	if op, _ := b.VaultOp(); op != v.Binding.VaultOp {
		t.Errorf("vault_op %s, want %s", op, v.Binding.VaultOp)
	}
	if v.Binding.Target != v.Policy.PD {
		t.Error("the vector's binding is not over the vector's policy")
	}
}
