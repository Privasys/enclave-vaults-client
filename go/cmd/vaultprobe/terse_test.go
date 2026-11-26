// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// A vault key's policy in stored form, as GetPolicy returns it (dev, 2026-11-25).
const storedV2 = `{"version":1,"principals":{"owner":{"Oidc":{"issuer":"https://privasys.id","sub":"s","required_roles":[]}},"managers":[],"auditors":[],"tees":[]},"operations":[{"ops":["DeleteKey","UpdatePolicy"],"principals":["Owner"],"requires":[{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}]},{"ops":["ExportKey"],"principals":["Owner"],"requires":[{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}]}],"mutability":{"owner_can":[],"manager_can":[],"immutable":["Owner"]},"lifecycle":{"ttl_seconds":7776000,"auto_migrate_to_next_attestation_profile":false}}`

func TestTerseVariantLeavesOutOnlyTheEmptyRoles(t *testing.T) {
	out, err := terseVariant([]byte(storedV2))
	if err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	_ = json.Unmarshal(out, &got)
	_ = json.Unmarshal([]byte(storedV2), &want)
	delete(want["principals"].(map[string]any)["owner"].(map[string]any)["Oidc"].(map[string]any), "required_roles")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the variant differs by more than the empty roles:\n%s", out)
	}
	if strings.Contains(string(out), "required_roles") {
		t.Fatal("required_roles still present")
	}
}

func TestTerseVariantSendsNothingUnlessSafe(t *testing.T) {
	cases := map[string]string{
		"update rule without binding 2": strings.Replace(storedV2, `"binding":2}}]},{"ops":["ExportKey"]`, `"binding":0}}]},{"ops":["ExportKey"]`, 1),
		"update rule with no condition": strings.Replace(storedV2, `"principals":["Owner"],"requires":[{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}]},{"ops":["ExportKey"]`, `"principals":["Owner"],"requires":[]},{"ops":["ExportKey"]`, 1),
		"no update rule":                strings.Replace(storedV2, `"DeleteKey","UpdatePolicy"`, `"DeleteKey"`, 1),
		"owner roles not empty":         strings.Replace(storedV2, `"required_roles":[]`, `"required_roles":["r"]`, 1),
		"owner roles absent":            strings.Replace(storedV2, `,"required_roles":[]`, ``, 1),
	}
	for name, raw := range cases {
		if raw == storedV2 {
			t.Fatalf("%s: the case did not change the policy", name)
		}
		if _, err := terseVariant([]byte(raw)); err == nil {
			t.Fatalf("%s: a variant was produced", name)
		}
	}
}

func TestBearersComeFromTwoLines(t *testing.T) {
	o, a, err := readBearers(bufio.NewReader(strings.NewReader("owner-token\r\natt-token\n")))
	if err != nil || o != "owner-token" || a != "att-token" {
		t.Fatalf("got %q %q %v", o, a, err)
	}
	if _, _, err := readBearers(bufio.NewReader(strings.NewReader("only-one\n"))); err == nil {
		t.Fatal("a missing second bearer was accepted")
	}
	if _, _, err := readBearers(bufio.NewReader(strings.NewReader("\natt\n"))); err == nil {
		t.Fatal("an empty owner bearer was accepted")
	}
}

func TestRuleLinesPrintOnlyTheRules(t *testing.T) {
	lines, err := ruleLines([]byte(storedV2))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"ops":["DeleteKey","UpdatePolicy"],"principals":["Owner"],"requires":[{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}]}`,
		`{"ops":["ExportKey"],"principals":["Owner"],"requires":[{"OidcStepUp":{"required_amr":["webauthn"],"operation_bound":true,"fresh_for_seconds":300,"binding":2}}]}`,
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("got %q", lines)
	}
	for _, l := range lines {
		for _, leak := range []string{`"sub"`, `"issuer"`, "mutability", "lifecycle", "ttl_seconds"} {
			if strings.Contains(l, leak) {
				t.Fatalf("a rule line carries %s: %s", leak, l)
			}
		}
	}
	// A rule with no conditions prints an empty list, not null.
	lines, err = ruleLines([]byte(`{"operations":[{"ops":["ExportKey"],"principals":[{"AnyTee":true}]}]}`))
	if err != nil || len(lines) != 1 || !strings.HasSuffix(lines[0], `"requires":[]}`) {
		t.Fatalf("got %q %v", lines, err)
	}
	if _, err := ruleLines([]byte(`{"version":1}`)); err == nil {
		t.Fatal("a policy without rules was accepted")
	}
}

func TestTeesSummaryCountsAndHashesOnly(t *testing.T) {
	raw := `{"version":1,"principals":{"owner":{"Oidc":{"issuer":"i","sub":"s"}},"tees":[{"Tdx":{"mr_td":"aa11"}},{"Tdx":{"mr_td":"bb22"}}]},"operations":[{"ops":["ExportKey"],"principals":["AnyTee"],"requires":[]}]}`
	tees, opsSum, err := teesSummary([]byte(raw))
	if err != nil || len(tees) != 2 {
		t.Fatalf("got %v %v", tees, err)
	}
	for _, s := range append(tees, opsSum) {
		if len(s) != 64 || strings.Contains(s, "aa11") || strings.Contains(s, "bb22") {
			t.Fatalf("not a bare SHA-256: %s", s)
		}
	}
	if tees[0] == tees[1] {
		t.Fatal("different entries hash alike")
	}
	first := sha256.Sum256([]byte(`{"Tdx":{"mr_td":"aa11"}}`))
	if tees[0] != hex.EncodeToString(first[:]) {
		t.Fatal("an entry's hash is not over its bytes as stored")
	}
	// The same operations, a different tees list: the operations hash is unchanged.
	other := strings.Replace(raw, `,{"Tdx":{"mr_td":"bb22"}}`, ``, 1)
	tees2, opsSum2, err := teesSummary([]byte(other))
	if err != nil || len(tees2) != 1 || opsSum2 != opsSum {
		t.Fatalf("got %v %s %v", tees2, opsSum2, err)
	}
	if _, _, err := teesSummary([]byte(`{"principals":{"tees":[]}}`)); err == nil {
		t.Fatal("a policy without rules was accepted")
	}
}

func TestExportVerdictNeverPrintsMaterial(t *testing.T) {
	secret := []byte("0123456789abcdef-SECRET-MATERIAL")
	k, v := exportVerdict(secret, nil)
	if k != verdictExported || !strings.HasPrefix(v, "FAIL: EXPORTED (sha256 of material: ") || strings.Contains(v, "SECRET") ||
		strings.Contains(v, hex.EncodeToString(secret)) {
		t.Fatalf("verdict leaks or is malformed: %s", v)
	}
}

// Only a refusal of the approval's binding passes; any other refusal is
// inconclusive and fails the run.
func TestExportVerdictAcceptsOnlyBindingRefusals(t *testing.T) {
	for _, msg := range []string{
		"no OperationRule grants ExportKey to caller with all conditions met: OidcStepUp: vault_op does not bind this operation (binding v2)",
		"no OperationRule grants ExportKey to caller with all conditions met: OidcStepUp: vault_op does not bind this operation (handle/measurement/policy_version/nonce/exp mismatch)",
		"no OperationRule grants ExportKey to caller with all conditions met: OidcStepUp: binding v2 required: the request must name its members",
		"no OperationRule grants ExportKey to caller with all conditions met: OidcStepUp: operation_bound required but this operation carries no binding context",
	} {
		if k, v := exportVerdict(nil, errors.New(msg)); k != verdictRefused || !strings.HasPrefix(v, "PASS: refused: ") {
			t.Errorf("%q: got %d %s", msg, k, v)
		}
	}
	for _, msg := range []string{
		"caller is in policy.principals but no OperationRule grants ExportKey",
		"key is not exportable",
		"key not found",
		"OIDC token audience mismatch",
		"dial tcp: connection refused",
		"no OperationRule grants ExportKey to caller with all conditions met: OidcStepUp: token amr [\"pwd\"] does not satisfy required [\"webauthn\"]",
	} {
		if k, v := exportVerdict(nil, errors.New(msg)); k != verdictInconclusive || !strings.HasPrefix(v, "FAIL: inconclusive: ") {
			t.Errorf("%q: got %d %s", msg, k, v)
		}
	}
}

func TestSplitList(t *testing.T) {
	if got := splitList(" a, ,b,"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatal(got)
	}
}
