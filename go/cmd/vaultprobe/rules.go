// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// teesSummary returns, from a key's raw policy (as GetPolicy returns it, in
// the vault's stored form), the number of entries in principals.tees, the
// SHA-256 of each entry's bytes as stored, and the SHA-256 of the operations
// block's bytes as stored. Nothing of an entry itself (no measurement field)
// is returned: two reads can be compared, an entry cannot be read back.
func teesSummary(raw []byte) (tees []string, opsSum string, err error) {
	var p struct {
		Principals struct {
			Tees []json.RawMessage `json:"tees"`
		} `json:"principals"`
		Operations json.RawMessage `json:"operations"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, "", err
	}
	if p.Operations == nil {
		return nil, "", errors.New("the policy has no operation rules")
	}
	for _, t := range p.Principals.Tees {
		sum := sha256.Sum256(t)
		tees = append(tees, hex.EncodeToString(sum[:]))
	}
	sum := sha256.Sum256(p.Operations)
	return tees, hex.EncodeToString(sum[:]), nil
}

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
