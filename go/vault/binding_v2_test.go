// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1.5}`, `{"a":9007199254740993}`, `{"a":1} {}`, `{"a":"\xff"}`} {
		if _, err := CanonicalJSON([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
