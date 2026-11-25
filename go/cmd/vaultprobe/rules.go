// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"errors"
)

// ruleLines returns a key's operation rules from its raw policy (as GetPolicy
// returns it), one compact JSON line per rule, in order: the rule's ops, its
// principals (as references such as "Owner" or {"Manager":0}) and its
// conditions. Nothing else of the policy is returned: not the principals'
// definitions (owner subject, measurements), the mutability or the lifecycle.
func ruleLines(raw []byte) ([]string, error) {
	var p struct {
		Operations []json.RawMessage `json:"operations"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Operations == nil {
		return nil, errors.New("the policy has no operation rules")
	}
	out := make([]string, 0, len(p.Operations))
	for _, r := range p.Operations {
		var rule struct {
			Ops        json.RawMessage `json:"ops"`
			Principals json.RawMessage `json:"principals"`
			Requires   json.RawMessage `json:"requires"`
		}
		if err := json.Unmarshal(r, &rule); err != nil {
			return nil, err
		}
		if rule.Requires == nil {
			rule.Requires = json.RawMessage("[]")
		}
		line, err := json.Marshal(struct {
			Ops        json.RawMessage `json:"ops"`
			Principals json.RawMessage `json:"principals"`
			Requires   json.RawMessage `json:"requires"`
		}{rule.Ops, rule.Principals, rule.Requires})
		if err != nil {
			return nil, err
		}
		out = append(out, string(line))
	}
	return out, nil
}
