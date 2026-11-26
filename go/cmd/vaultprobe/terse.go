// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"errors"
	"strings"
)

// terseVariant returns the same policy as raw (a policy as GetPolicy returns
// it, in stored form) with one default left out: the owner's required_roles
// when it is the empty list. It means exactly the same policy, so even a vault
// that wrongly accepted it would change nothing; a vault that takes a policy
// update only in its stored form must refuse it. It refuses to produce a
// variant unless every rule granting UpdatePolicy asks for a binding 2
// step-up (so no approval-free update could pass) and the owner's
// required_roles is present and empty.
func terseVariant(raw []byte) ([]byte, error) {
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if err := updateRulesTakeBinding2(p); err != nil {
		return nil, err
	}
	principals, _ := p["principals"].(map[string]any)
	owner, _ := principals["owner"].(map[string]any)
	oidc, _ := owner["Oidc"].(map[string]any)
	if oidc == nil {
		return nil, errors.New("the owner is not an Oidc principal")
	}
	roles, present := oidc["required_roles"]
	list, isList := roles.([]any)
	if !present || !isList || len(list) != 0 {
		return nil, errors.New("the owner's required_roles is not the empty list: no harmless default to leave out")
	}
	delete(oidc, "required_roles")
	return json.Marshal(p)
}

// updateRulesTakeBinding2 checks that at least one rule grants UpdatePolicy
// and every such rule requires an OidcStepUp with binding 2.
func updateRulesTakeBinding2(p map[string]any) error {
	ops, _ := p["operations"].([]any)
	found := false
	for _, r := range ops {
		rule, _ := r.(map[string]any)
		names, _ := json.Marshal(rule["ops"])
		if !strings.Contains(string(names), `"UpdatePolicy"`) {
			continue
		}
		found = true
		requires, _ := rule["requires"].([]any)
		bound := false
		for _, c := range requires {
			cond, _ := c.(map[string]any)
			step, _ := cond["OidcStepUp"].(map[string]any)
			if b, ok := step["binding"].(float64); ok && b == 2 {
				bound = true
			}
		}
		if !bound {
			return errors.New("a rule grants UpdatePolicy without a binding 2 step-up: refusing to send anything")
		}
	}
	if !found {
		return errors.New("no rule grants UpdatePolicy")
	}
	return nil
}

// splitList splits a comma-separated list, dropping empty items.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
