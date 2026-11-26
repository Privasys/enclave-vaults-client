// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

var (
	memberA = strings.Repeat("a", 64)
	memberB = strings.Repeat("0", 63) + "b"
)

func TestBindingV2Text(t *testing.T) {
	b := BindingV2{
		Members: []string{memberA, memberB}, Op: BindUpdatePolicy,
		Handle: "apps.privasys.org/app-1/key", Target: strings.Repeat("c", 64),
		PolicyVersion: 3, Approver: OidcApprover(0, "user-1"),
		Nonce: "AAAAAAAAAAAAAAAAAAAAAA", Exp: 1764000600,
	}
	got, err := b.Text()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"privasys-vault-approval/v2", "2", memberB, memberA,
		"update_policy", "apps.privasys.org/app-1/key", strings.Repeat("c", 64), "3",
		"oidc:0:user-1", "-", "AAAAAAAAAAAAAAAAAAAAAA", "1764000600",
	}, "\n")
	if got != want {
		t.Fatalf("text:\n%s\nwant:\n%s", got, want)
	}
	op, _ := b.VaultOp()
	sum := sha256.Sum256([]byte(want))
	if op != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("vault_op is not b64u(H(text))")
	}

	// A delete binds no target.
	b.Op, b.Target = BindDelete, ""
	got, _ = b.Text()
	if !strings.Contains(got, "\ndelete\napps.privasys.org/app-1/key\n-\n3\n") {
		t.Fatalf("delete target is not '-':\n%s", got)
	}
}

func TestBindingV2Refuses(t *testing.T) {
	ok := BindingV2{Members: []string{memberA}, Op: BindPromote, Handle: "h", Approver: "x", Nonce: "n", Exp: 1}
	if _, err := ok.Text(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*BindingV2){
		"no members":      func(b *BindingV2) { b.Members = nil },
		"duplicate":       func(b *BindingV2) { b.Members = []string{memberA, memberA} },
		"uppercase":       func(b *BindingV2) { b.Members = []string{strings.ToUpper(memberB)} },
		"short member":    func(b *BindingV2) { b.Members = []string{"ab"} },
		"unknown op":      func(b *BindingV2) { b.Op = "rotate" },
		"newline":         func(b *BindingV2) { b.Handle = "a\nb" },
		"carriage return": func(b *BindingV2) { b.Approver = "oidc:0:a\rb" },
		"no nonce":        func(b *BindingV2) { b.Nonce = "" },
		"no exp":          func(b *BindingV2) { b.Exp = 0 },
	} {
		b := ok
		mut(&b)
		if _, err := b.Text(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMemberID(t *testing.T) {
	pub := make([]byte, 65)
	pub[0] = 0x04
	pub[64] = 1
	got, err := MemberID(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte("privasys-vault-member-v1\n"), pub...))
	if got != hex.EncodeToString(sum[:]) {
		t.Fatal("member id")
	}
	if _, err := MemberID(pub[1:]); err == nil {
		t.Fatal("a compressed or short key was accepted")
	}
}

func TestCanonicalJSON(t *testing.T) {
	// RFC 8785 §3.2.3: names sorted as UTF-16 code units, so U+1F600 (a
	// surrogate pair, D83D) sorts before U+FB33.
	in := `{"\u20ac":"Euro","\r":"CR","\ufb33":"Hebrew","1":"One","\ud83d\ude00":"Smiley","\u0080":"Control","\u00f6":"Latin"}`
	want := "{\"\\r\":\"CR\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin\",\"\u20ac\":\"Euro\",\"\U0001F600\":\"Smiley\",\"\ufb33\":\"Hebrew\"}"
	got, err := CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}

	got, err = CanonicalJSON([]byte(` { "b" : [ 1 , 2.0, -0, 1e3, true, null ], "a" : "<&>\u2028/\u001f" } `))
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":\"<&>\u2028/\\u001f\",\"b\":[1,2,0,1000,true,null]}"; string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}

	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1.5}`, `{"a":9007199254740993}`, `{"a":1} {}`, `{"a":1} x`, `{"a":"\xff"}`, `{"a":"\ud800"}`, `{"a":"�"}`} {
		if _, err := CanonicalJSON([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// The binding v2 vector, computed by hand from the binding text's definition.
func TestBindingV2SpecVector(t *testing.T) {
	b := BindingV2{
		Members:       []string{strings.Repeat("2", 64), strings.Repeat("1", 64)},
		Op:            BindUpdatePolicy,
		Handle:        "apps.privasys.org/0123456789abcdef0123456789abcdef/data-v2",
		Target:        "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
		PolicyVersion: 3, Approver: "oidc:0:test-subject-1",
		Nonce: "AAECAwQFBgcICQoLDA0ODw", Exp: 1764000600,
	}
	text, err := b.Text()
	if err != nil {
		t.Fatal(err)
	}
	if len(text) != 356 {
		t.Fatalf("text is %d bytes, the vector's is 356", len(text))
	}
	sum := sha256.Sum256([]byte(text))
	if hex.EncodeToString(sum[:]) != "f4fe5392066464c3e92ca26c442af4f53d2009e87532a398923cea5f95f31b23" {
		t.Fatal("H(text) differs from the vector")
	}
	if op, _ := b.VaultOp(); op != "9P5TkgZkZMPpLKJsRCr09T0gCeh1MqOYkjzqX5XzGyM" {
		t.Fatalf("vault_op %s differs from the vector", op)
	}
}

func TestPolicyDigestNames(t *testing.T) {
	if _, err := PolicyDigestJSON([]byte(`{"né":1}`)); err == nil {
		t.Fatal("a non-ASCII member name was accepted in a policy")
	}
	a, err := PolicyDigestJSON([]byte(`{"b":"café","a":[{"y":1,"x":[2]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := PolicyDigestJSON([]byte(`{"a":[{"x":[2],"y":1}],"b":"café"}`))
	if a != b {
		t.Fatal("the same policy written two ways gave two digests")
	}
}

// identityQuote is an unsigned SGX v3 quote carrying a member id and billing id.
func identityQuote(mid, billing string, mr []byte) []byte {
	quote := make([]byte, sgxQuoteReportData+64)
	quote[0] = 3
	copy(quote[sgxQuoteMrEnclave:], mr)
	rd := IdentityReportData(mid, billing)
	copy(quote[sgxQuoteReportData:], rd[:])
	return quote
}

func TestVaultIdentityCheckConsistent(t *testing.T) {
	pub := make([]byte, 65)
	pub[0], pub[64] = 0x04, 7
	mid, _ := MemberID(pub)
	mr := strings.Repeat("ab", 32)
	mrb, _ := hex.DecodeString(mr)
	quote := identityQuote(mid, "bill", mrb)
	id := VaultIdentity{MemberID: mid, MemberPublicKey: hex.EncodeToString(pub), BillingID: "bill",
		MRENCLAVE: mr, QuoteB64: base64.RawURLEncoding.EncodeToString(quote)}
	if err := id.CheckConsistent(); err != nil {
		t.Fatal(err)
	}
	withQuote := func(f func(q []byte)) string {
		q := append([]byte(nil), quote...)
		f(q)
		return base64.RawURLEncoding.EncodeToString(q)
	}
	for name, mut := range map[string]func(*VaultIdentity){
		"member id":  func(v *VaultIdentity) { v.MemberID = memberA },
		"billing":    func(v *VaultIdentity) { v.BillingID = "other" },
		"mrenclave":  func(v *VaultIdentity) { v.MRENCLAVE = strings.Repeat("cd", 32) },
		"short":      func(v *VaultIdentity) { v.QuoteB64 = base64.RawURLEncoding.EncodeToString(quote[:100]) },
		"padded b64": func(v *VaultIdentity) { v.QuoteB64 += "=" },
		"v5 quote":   func(v *VaultIdentity) { v.QuoteB64 = withQuote(func(q []byte) { q[0] = 5 }) },
		"tdx quote":  func(v *VaultIdentity) { v.QuoteB64 = withQuote(func(q []byte) { q[4] = 0x81 }) },
	} {
		v := id
		mut(&v)
		if err := v.CheckConsistent(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGetVaultIdentityNeedsPinnedMRENCLAVE(t *testing.T) {
	c := &Client{}
	if _, err := c.GetVaultIdentity(context.Background()); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("an unpinned connection was used: %v", err)
	}
}

func TestDeleteAfterTarget(t *testing.T) {
	got, err := DeleteAfterTarget("apps.privasys.org/new/k", strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("privasys-delete-after-v1\napps.privasys.org/new/k\n" + strings.Repeat("e", 64)))
	if got != hex.EncodeToString(sum[:]) {
		t.Fatal("delete_after target")
	}
	created, _ := DeleteAfterTarget("apps.privasys.org/new/k", "")
	sum = sha256.Sum256([]byte("privasys-delete-after-v1\napps.privasys.org/new/k\n-"))
	if created != hex.EncodeToString(sum[:]) {
		t.Fatal("a created successor's target is not '-'")
	}
	if _, err := DeleteAfterTarget("", "x"); err == nil {
		t.Fatal("no successor accepted")
	}
	if _, err := DeleteAfterTarget("a\nb", ""); err == nil {
		t.Fatal("a line break accepted")
	}
	if BindDeleteAfter.MaxTTLSeconds() != 86400 || BindDelete.MaxTTLSeconds() != 600 {
		t.Fatal("ttl per op")
	}
}

func TestApprovalRequestsCarryTheBindingMembers(t *testing.T) {
	c := &Client{opts: DialOptions{BindingMembers: []string{memberA, memberB}}}
	raw, err := json.Marshal(vaultRequest{DeleteKey: &handleApprovalsReq{Handle: "h", Binding: c.bindingMembers()}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"DeleteKey":{"handle":"h","binding":{"members":["` + memberB + `","` + memberA + `"]}}}`
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}
	plain, _ := json.Marshal(vaultRequest{DeleteKey: &handleApprovalsReq{Handle: "h", Binding: (&Client{}).bindingMembers()}})
	if strings.Contains(string(plain), "binding") {
		t.Fatalf("a v1 request carries a binding: %s", plain)
	}
}

func TestUpdatePolicyRawSendsThePolicyAsGiven(t *testing.T) {
	// Fields in a non-struct order, one known field left out: the vault must
	// receive exactly these, so its digest is the one the owner approved.
	policy := json.RawMessage(`{"operations": [], "lifecycle": {"ttl_seconds": 0}}`)
	c := &Client{opts: DialOptions{BindingMembers: []string{memberA}}}
	raw, err := c.updatePolicyRawPayload("h", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"UpdatePolicy":{"handle":"h","new_policy":{"operations":[],"lifecycle":{"ttl_seconds":0}},"binding":{"members":["` + memberA + `"]}}}`
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}
	var sent struct {
		UpdatePolicy struct {
			NewPolicy json.RawMessage `json:"new_policy"`
		}
	}
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	a, err := PolicyDigestJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := PolicyDigestJSON(sent.UpdatePolicy.NewPolicy); a != b {
		t.Fatalf("digest changed on the wire: %s -> %s", a, b)
	}
}

func TestDeleteKeyAfterNamesItsSuccessor(t *testing.T) {
	c := &Client{opts: DialOptions{BindingMembers: []string{memberA}}}
	raw, err := c.deleteKeyAfterPayload("apps/x/v1", "apps/x/v2", "-", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"DeleteKey":{"handle":"apps/x/v1","binding":{"members":["` + memberA + `"]},"after":{"successor":"apps/x/v2","successor_target":"-"}}}`
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}
	if err := c.DeleteKeyAfter(context.Background(), "apps/x/v1", "apps/x/v1", "-"); err == nil {
		t.Fatal("a key was accepted as its own successor")
	}
}
