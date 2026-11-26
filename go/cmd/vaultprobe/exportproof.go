// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// exportProof asks privasys.id for ONE v1 "policy-update" approval for the key
// (the owner approves it in the wallet), then presents that approval to
// ExportKey on each member and reports only whether the vault refused it. It
// proves that a rules-change approval cannot export the key. The approval is
// kept in memory, never printed, and left to expire; no rules change is made.
// If a vault does export, only the SHA-256 of what it returned is printed, and
// the material is overwritten. It passes only when every member refused the
// approval because it does not bind the export.
func exportProof(ctx context.Context, eps []string, policy *ratls.VerificationPolicy, owner, issuer, audience, handle string) error {
	if len(eps) == 0 {
		return errors.New("no members")
	}
	// The key's current policy version, read as the owner from the first member.
	c, err := vault.Dial(ctx, vault.VaultRegistration{ID: eps[0], Endpoint: eps[0], Status: "probe"},
		vault.DialOptions{AuthToken: vault.StaticToken(owner), VaultPolicy: policy})
	if err != nil {
		return fmt.Errorf("dial %s: %w", eps[0], err)
	}
	_, version, err := c.GetPolicyRaw(ctx, handle)
	c.Close()
	if err != nil {
		return fmt.Errorf("read policy version: %w", err)
	}
	fmt.Printf("export proof on %s (policy_version %d)\n", handle, version)

	token, err := policyUpdateApproval(ctx, issuer, owner, audience, handle, version)
	if err != nil {
		return err
	}
	// Every member must give a verdict: a member not reached, or one that
	// refused for any reason but the approval's binding, fails the check.
	var exported, notChecked, inconclusive []string
	for _, ep := range eps {
		c, err := vault.Dial(ctx, vault.VaultRegistration{ID: ep, Endpoint: ep, Status: "probe"},
			vault.DialOptions{AuthToken: vault.StaticToken(token), VaultPolicy: policy})
		if err != nil {
			fmt.Printf("== %s: FAIL: not checked (dial: %v)\n", ep, err)
			notChecked = append(notChecked, ep)
			continue
		}
		material, xerr := c.ExportKey(ctx, handle)
		c.Close()
		kind, line := exportVerdict(material, xerr)
		fmt.Printf("== %s: %s\n", ep, line)
		switch kind {
		case verdictExported:
			exported = append(exported, ep)
		case verdictInconclusive:
			inconclusive = append(inconclusive, ep)
		}
		for i := range material {
			material[i] = 0
		}
	}
	token = ""
	var problems []string
	if len(exported) > 0 {
		problems = append(problems, "EXPORTED the key with a rules-change approval: "+strings.Join(exported, ", "))
	}
	if len(inconclusive) > 0 {
		problems = append(problems, "inconclusive (refused for a reason other than the approval's binding): "+strings.Join(inconclusive, ", "))
	}
	if len(notChecked) > 0 {
		problems = append(problems, "not checked (dial failed): "+strings.Join(notChecked, ", "))
	}
	if len(problems) > 0 {
		return errors.New("export check failed: " + strings.Join(problems, "; "))
	}
	return nil
}

// bindingRefusals are the vault's refusals of an approval that does not bind
// the operation it is presented to: the only refusals that show a rules-change
// approval cannot export the key. Any other refusal (audience, sign-in, an
// unknown or non-exportable key, the network) proves nothing about the
// approval.
var bindingRefusals = []string{
	"vault_op does not bind this operation",
	"OidcStepUp: operation_bound required but this operation carries no binding context",
	"OidcStepUp: binding v2 required",
	"the approval does not name this vault",
}

type verdict int

const (
	verdictRefused verdict = iota
	verdictInconclusive
	verdictExported
)

// exportVerdict classifies one member's answer and gives the line printed for
// it: the expected binding refusal, a refusal for another reason
// (inconclusive), or that the vault exported, with only the SHA-256 of what it
// returned.
func exportVerdict(material []byte, err error) (verdict, string) {
	if err != nil {
		if isBindingRefusal(err) {
			return verdictRefused, "PASS: refused: " + err.Error()
		}
		return verdictInconclusive, "FAIL: inconclusive: " + err.Error()
	}
	sum := sha256.Sum256(material)
	return verdictExported, "FAIL: EXPORTED (sha256 of material: " + hex.EncodeToString(sum[:]) + ")"
}

// isBindingRefusal reports whether err is the vault refusing the approval
// because it does not bind the export.
func isBindingRefusal(err error) bool {
	msg := err.Error()
	for _, r := range bindingRefusals {
		if strings.Contains(msg, r) {
			return true
		}
	}
	return false
}

// policyUpdateApproval opens a v1 "policy-update" approval at privasys.id (the
// same begin and token poll as the CLI's step-up) and waits up to 5 minutes for
// the owner to approve it in the wallet. The approval is returned, never shown.
func policyUpdateApproval(ctx context.Context, issuer, bearer, audience, handle string, version uint32) (string, error) {
	issuer = strings.TrimRight(issuer, "/")
	begin, _ := json.Marshal(map[string]any{
		"operation":          "policy-update",
		"handle":             handle,
		"measurement_digest": "",
		"policy_version":     version,
		"ttl_seconds":        300,
		"audience":           audience,
		"context": map[string]string{
			"summary": "vaultprobe export check: this approval must be refused; no rules change is made.",
		},
	})
	opts, err := idpCall(ctx, http.MethodPost, issuer+"/fido2/vault-approval/begin", bearer, begin)
	if err != nil {
		return "", fmt.Errorf("approval begin: %w", err)
	}
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(opts.body, &o) != nil || o.PublicKey.Challenge == "" {
		return "", errors.New("approval begin: no challenge")
	}
	fmt.Println("waiting for the owner's approval in the wallet (up to 5 minutes)...")
	poll := issuer + "/fido2/vault-approval/token?challenge=" + url.QueryEscape(o.PublicKey.Challenge)
	deadline := time.Now().Add(5*time.Minute + 20*time.Second)
	for time.Now().Before(deadline) {
		r, err := idpCall(ctx, http.MethodGet, poll, bearer, nil)
		if err != nil {
			return "", fmt.Errorf("approval poll: %w", err)
		}
		if r.status != http.StatusAccepted {
			var t struct {
				AccessToken string `json:"access_token"`
			}
			if json.Unmarshal(r.body, &t) != nil || t.AccessToken == "" {
				return "", errors.New("approval poll: no access_token")
			}
			fmt.Println("approved")
			return t.AccessToken, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return "", errors.New("approval timed out")
}

type idpResponse struct {
	status int
	body   []byte
}

// idpCall sends one request to privasys.id with the owner bearer. An error
// status returns its code and body (the IdP's reason; no token is in it).
func idpCall(ctx context.Context, method, u, bearer string, body []byte) (idpResponse, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return idpResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return idpResponse{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return idpResponse{}, fmt.Errorf("%d: %s", resp.StatusCode, data)
	}
	return idpResponse{status: resp.StatusCode, body: data}, nil
}
