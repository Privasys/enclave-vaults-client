// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Command vaultprobe reads keys on EVERY member of a vault constellation, one
// member at a time, for an independent view of what each vault holds. It is
// read only, except for an optional refusal check that sends one request the
// vaults must refuse.
//
// It holds no sign-in code and stores nothing. The two bearers are read from
// standard input, one per line, and kept in memory only:
//
//	line 1: the key owner's bearer for the vault audience
//	line 2: a bearer for the attestation server (quote verification)
//
// For example, with the installed CLI (which alone touches the sign-in store):
//
//	{ privasys --test auth print-access-token --audience privasys-platform-test
//	  privasys --test auth print-access-token --audience attestation-server
//	} | vaultprobe -mrenclave <hex> -members host:port,host:port -handle <h> [-handle <h>] [-refuse <h>]
//
// Per member and handle it prints GetKeyInfo (or the tombstone of a deleted
// key), the raw policy's version and SHA-256, and the audit log. With -refuse,
// it sends the named key's own policy with one default left out (the owner's
// empty required_roles: the same policy, not in the vault's stored form), with
// NO approval, to each member, and checks that the vault refuses it before
// anything else and that the policy version is unchanged (formats §5.1).
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// notStoredForm starts the vault's refusal of a policy not sent in stored form.
const notStoredForm = "new_policy is not in the vault's stored form"

type handles []string

func (h *handles) String() string     { return strings.Join(*h, ",") }
func (h *handles) Set(v string) error { *h = append(*h, v); return nil }

func main() {
	var (
		mre     = flag.String("mrenclave", "", "expected vault MRENCLAVE (hex)")
		members = flag.String("members", "", "comma-separated vault endpoints (host:port)")
		attURL  = flag.String("attestation-server", "https://as.privasys.org/verify", "quote verification endpoint")
		tcb     = flag.String("tcb", "ConfigurationAndSWHardeningNeeded", "comma-separated acceptable TCB statuses")
		refuse  = flag.String("refuse", "", "run the stored-form refusal check on this handle")
		hs      handles
	)
	flag.Var(&hs, "handle", "a key handle to read (repeatable)")
	flag.Parse()
	if err := run(*mre, *members, *attURL, *tcb, *refuse, hs); err != nil {
		fmt.Fprintln(os.Stderr, "vaultprobe:", err)
		os.Exit(1)
	}
}

func run(mre, members, attURL, tcb, refuse string, hs []string) error {
	m, err := hex.DecodeString(mre)
	if err != nil || len(m) != 32 {
		return errors.New("-mrenclave must be 64 hex digits")
	}
	eps := splitList(members)
	if len(eps) == 0 || (len(hs) == 0 && refuse == "") {
		return errors.New("need -members and at least one -handle or -refuse")
	}
	owner, att, err := readBearers(bufio.NewReader(os.Stdin))
	if err != nil {
		return err
	}
	var statuses []ratls.TCBStatus
	for _, s := range splitList(tcb) {
		statuses = append(statuses, ratls.TCBStatus(s))
	}
	policy := &ratls.VerificationPolicy{
		TEE:       ratls.TeeTypeSGX,
		MRENCLAVE: m,
		QuoteVerification: &ratls.QuoteVerificationConfig{
			Endpoint: attURL, Token: att, AcceptableTCBStatuses: statuses,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fmt.Println("vaultprobe at", time.Now().UTC().Format(time.RFC3339))
	failed := false
	for _, ep := range eps {
		c, err := vault.Dial(ctx, vault.VaultRegistration{ID: ep, Endpoint: ep, Status: "probe"},
			vault.DialOptions{AuthToken: vault.StaticToken(owner), VaultPolicy: policy})
		if err != nil {
			fmt.Printf("== %s: dial: %v\n", ep, err)
			failed = true
			continue
		}
		fmt.Printf("== %s\n", ep)
		for _, h := range hs {
			readKey(ctx, c, h)
		}
		if refuse != "" && !refusalCheck(ctx, c, refuse) {
			failed = true
		}
		c.Close()
	}
	if failed {
		return errors.New("one or more checks failed (see above)")
	}
	return nil
}

// readBearers reads the two bearers from r. They are never printed.
func readBearers(r *bufio.Reader) (owner, att string, err error) {
	read := func(what string) (string, error) {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			if err == nil {
				err = errors.New("empty line")
			}
			return "", fmt.Errorf("reading the %s bearer from stdin: %w", what, err)
		}
		return line, nil
	}
	if owner, err = read("owner"); err != nil {
		return "", "", err
	}
	if att, err = read("attestation-server"); err != nil {
		return "", "", err
	}
	return owner, att, nil
}

func readKey(ctx context.Context, c *vault.Client, h string) {
	fmt.Printf("  -- %s\n", h)
	ki, err := c.GetKeyInfo(ctx, h)
	var kd *vault.ErrKeyDeleted
	switch {
	case err == nil:
		fmt.Printf("     info: type=%s policy_version=%d created_at=%d expires_at=%d created_by_owner_approval=%v renewed_in_place_from=%q\n",
			ki.KeyType, ki.PolicyVersion, ki.CreatedAt, ki.ExpiresAt, ki.CreatedByOwnerApproval, ki.RenewedInPlaceFrom)
	case errors.As(err, &kd):
		t := kd.Tombstone
		fmt.Printf("     TOMBSTONE: op=%s deleted_at=%d successor=%s expires_at=%d key_type=%s\n",
			t.Op, t.DeletedAt, t.Successor, t.ExpiresAt, t.KeyType)
	default:
		fmt.Printf("     info: %v\n", err)
	}
	if raw, ver, err := c.GetPolicyRaw(ctx, h); err != nil {
		fmt.Printf("     policy: %v\n", err)
	} else {
		sum := sha256.Sum256(raw)
		fmt.Printf("     policy: version=%d sha256=%s\n", ver, hex.EncodeToString(sum[:]))
	}
	entries, _, err := c.ReadAuditLog(ctx, h, 0, 1024)
	if err != nil {
		fmt.Printf("     audit: %v\n", err)
		return
	}
	for _, e := range entries {
		fmt.Printf("     audit %3d %s %-22s %-7v %s | %s\n", e.Seq,
			time.Unix(int64(e.Ts), 0).UTC().Format(time.RFC3339), e.Op, e.Decision, e.Caller, e.Reason)
	}
}

// refusalCheck sends the key's own policy, not in stored form, with no
// approval, and reports whether the vault refused it as formats §5.1 says and
// left the policy unchanged.
func refusalCheck(ctx context.Context, c *vault.Client, h string) bool {
	fmt.Printf("  -- refusal check on %s\n", h)
	raw, before, err := c.GetPolicyRaw(ctx, h)
	if err != nil {
		fmt.Printf("     FAIL: read policy: %v\n", err)
		return false
	}
	terse, err := terseVariant(raw)
	if err != nil {
		fmt.Printf("     SKIP (nothing sent): %v\n", err)
		return false
	}
	_, uerr := c.UpdatePolicyRaw(ctx, h, terse)
	_, after, rerr := c.GetPolicyRaw(ctx, h)
	ok := uerr != nil && strings.Contains(uerr.Error(), notStoredForm) && rerr == nil && after == before
	verdict := "FAIL"
	if ok {
		verdict = "PASS"
	}
	fmt.Printf("     %s: answer=%v; policy_version %d -> %d\n", verdict, uerr, before, after)
	return ok
}
