// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

// Resharing a threshold key: the SAME handle and the SAME public key, fresh
// shares, held by the vaults of the target constellation (a renewal in place
// when it is the key's own constellation, a move otherwise). As for a Shamir
// secret's renewal, the client drives it and the owner approves it in the
// wallet: the old vaults deal their shares only against a fresh step-up bound
// to exactly this move (the resharing context).

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type frostTargetMessage struct {
	DhPublicB64 string `json:"dh_public_b64"`
	QuoteB64    string `json:"quote_b64"`
}

type frostDealMessage struct {
	CommitmentB64 []string `json:"commitment_b64"`
	SealedB64     string   `json:"sealed_b64"`
}

type frostReshareTarget1Req struct {
	Session                string   `json:"session"`
	Handle                 string   `json:"handle"`
	Grant                  string   `json:"grant"`
	Index                  uint16   `json:"index"`
	Threshold              uint16   `json:"threshold"`
	Vaults                 []string `json:"vaults"`
	Helpers                []uint16 `json:"helpers"`
	OldPublicKeyPackageB64 string   `json:"old_public_key_package_b64"`
	// The owner's create approval, for a re-created name new on this vault
	// (formats §9.3.1).
	Binding *bindingMembers `json:"binding,omitempty"`
}

type frostReshareDealReq struct {
	Session         string                        `json:"session"`
	Handle          string                        `json:"handle"`
	Helpers         []uint16                      `json:"helpers"`
	Threshold       uint16                        `json:"threshold"`
	Vaults          []string                      `json:"vaults"`
	TargetMrenclave string                        `json:"target_mrenclave"`
	Targets         map[uint16]frostTargetMessage `json:"targets"`
}

type frostReshareTarget2Req struct {
	Session string                        `json:"session"`
	Handle  string                        `json:"handle"`
	Targets map[uint16]frostTargetMessage `json:"targets"`
	Deals   map[uint16]frostDealMessage   `json:"deals"`
}

// ReshareContext is the 32-byte value a resharing binds: the key (handle and
// group key), the helpers (old participant indices), the new threshold, the
// new vaults and their build. The owner's wallet approval carries it (hex) in
// its measurement slot; the vaults recompute it.
func ReshareContext(handle string, groupKey []byte, helpers []uint16, threshold uint16,
	vaults []string, targetMrenclave []byte) []byte {
	h := sha256.New()
	u64 := func(n int) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		h.Write(b[:])
	}
	u16 := func(n uint16) {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], n)
		h.Write(b[:])
	}
	h.Write([]byte("privasys-vault-frost-reshare-v1"))
	u64(len(handle))
	h.Write([]byte(handle))
	u64(len(groupKey))
	h.Write(groupKey)
	u64(len(helpers))
	for _, i := range helpers {
		u16(i)
	}
	u16(threshold)
	u64(len(vaults))
	for _, v := range vaults {
		u64(len(v))
		h.Write([]byte(v))
	}
	h.Write(targetMrenclave)
	return h.Sum(nil)
}

// swapToken is an AuthTokenSource whose token can be replaced (the owner's
// session for reading, then the step-up for dealing).
type swapToken struct {
	mu  sync.Mutex
	tok string
}

func (s *swapToken) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tok, nil
}

func (s *swapToken) set(t string) {
	s.mu.Lock()
	s.tok = t
	s.mu.Unlock()
}

// ReshareParams describes one resharing.
type ReshareParams struct {
	Handle string
	// Grant is a key-creation grant for Handle (FrostEd25519, not
	// exportable), bound to the target dial's client certificate.
	Grant string
	// Threshold of the reshared key (2..len(target vaults)).
	Threshold int
	// Home is the constellation holding the key now; it is dialled with the
	// owner's session (HomeToken).
	Home      []string
	HomeDial  DialOptions
	HomeToken string
	// Target is the constellation the key moves to (Home itself for a
	// renewal in place), dialled with the grant's client certificate.
	Target          []string
	TargetDial      DialOptions
	TargetMrenclave string
	// InPlace: Target is the key's own constellation (same vaults).
	InPlace bool
	// StepUp returns the owner's bearer with a fresh wallet approval of
	// operation "reshare" for Handle, whose measurement slot is
	// a.ContextHex, at a.PolicyVersion.
	StepUp func(ctx context.Context, a ReshareApproval) (string, error)
}

// ReshareApproval is what the owner approves: the resharing context and every
// input of it, so a wallet can recompute ContextHex from what it displays.
type ReshareApproval struct {
	ContextHex      string
	PolicyVersion   uint32
	GroupKey        []byte
	Helpers         []uint16
	Threshold       uint16
	Vaults          []string
	TargetMrenclave string
}

// ReshareThresholdKey renews a threshold key, or moves it to another
// constellation, keeping its handle and public key. On success every target
// vault holds a fresh share; a move destroys the old vaults' shares, a
// renewal in place drops the previous records. On a failure part-way it
// rolls back (in place) or removes the new copies (a move).
func ReshareThresholdKey(ctx context.Context, p ReshareParams) (*ThresholdKey, error) {
	// The old key, from its vaults.
	homeTok := &swapToken{tok: p.HomeToken}
	homeOpts := p.HomeDial
	homeOpts.AuthToken = homeTok
	type helper struct {
		c    *Client
		info *ThresholdKeyInfo
		pv   uint32
		ep   string
	}
	var helpers []helper
	var unreachable []string
	defer func() {
		for _, h := range helpers {
			h.c.Close()
		}
	}()
	var pkp []byte
	var threshold0 int
	for _, ep := range p.Home {
		c, err := Dial(ctx, VaultRegistration{ID: ep, Endpoint: ep, Status: "static"}, homeOpts)
		if err != nil {
			unreachable = append(unreachable, fmt.Sprintf("%s: %v", ep, err))
			continue
		}
		ki, err := c.GetKeyInfo(ctx, p.Handle)
		if err != nil || ki.Threshold == nil {
			c.Close()
			if err == nil {
				err = errors.New("not a threshold key")
			}
			unreachable = append(unreachable, fmt.Sprintf("%s: %v", ep, err))
			continue
		}
		if pkp == nil {
			pkp, threshold0 = ki.Threshold.PublicKeyPackage, int(ki.Threshold.Threshold)
		}
		helpers = append(helpers, helper{c: c, info: ki.Threshold, pv: ki.PolicyVersion, ep: ep})
	}
	if len(helpers) < threshold0 || threshold0 == 0 {
		return nil, fmt.Errorf("only %d of the old vaults hold the key (need %d): %v", len(helpers), threshold0, unreachable)
	}
	sort.Slice(helpers, func(i, j int) bool { return helpers[i].info.Index < helpers[j].info.Index })
	helpers = helpers[:threshold0]
	helperIdx := make([]uint16, len(helpers))
	for i, h := range helpers {
		helperIdx[i] = h.info.Index
		if h.pv != helpers[0].pv {
			return nil, errors.New("the old vaults disagree on the key's policy version; retry")
		}
	}

	// The new vaults, round 1.
	n := len(p.Target)
	if p.Threshold < 2 || p.Threshold > n {
		return nil, fmt.Errorf("threshold must be 2..%d, got %d", n, p.Threshold)
	}
	targets := make([]*Client, n)
	defer func() {
		for _, c := range targets {
			if c != nil {
				c.Close()
			}
		}
	}()
	for i, ep := range p.Target {
		c, err := Dial(ctx, VaultRegistration{ID: ep, Endpoint: ep, Status: "static"}, p.TargetDial)
		if err != nil {
			return nil, fmt.Errorf("new vault %s: %w", ep, err)
		}
		targets[i] = c
	}
	session, err := NewFrostSession()
	if err != nil {
		return nil, err
	}
	abort := func() {
		for _, c := range targets {
			_, _ = c.call(ctx, vaultRequest{FrostReshareAbort: &frostSessionReq{Session: session}})
		}
	}
	pkpB64 := base64.RawURLEncoding.EncodeToString(pkp)
	tmsg := make(map[uint16]frostTargetMessage, n)
	for i, c := range targets {
		resp, err := c.call(ctx, vaultRequest{FrostReshareTarget1: &frostReshareTarget1Req{
			Session: session, Handle: p.Handle, Grant: p.Grant, Index: uint16(i + 1),
			Threshold: uint16(p.Threshold), Vaults: p.Target, Helpers: helperIdx,
			OldPublicKeyPackageB64: pkpB64,
			Binding:                c.createBinding(p.Handle),
		}})
		if err == nil && resp.FrostReshareTarget == nil {
			err = ErrUnexpectedResponse
		}
		if err != nil {
			abort()
			return nil, fmt.Errorf("new vault %s: %w", p.Target[i], err)
		}
		tmsg[uint16(i+1)] = frostTargetMessage{
			DhPublicB64: b64(resp.FrostReshareTarget.DhPublic), QuoteB64: b64(resp.FrostReshareTarget.Quote),
		}
	}

	// The owner's approval of exactly this move, then the deals.
	mr, err := hex.DecodeString(p.TargetMrenclave)
	if err != nil || len(mr) != 32 {
		abort()
		return nil, errors.New("target mrenclave must be 32 bytes of hex")
	}
	groupKey, err := groupKeyFromInfo(helpers[0].c, ctx, p.Handle)
	if err != nil {
		abort()
		return nil, err
	}
	rc := ReshareContext(p.Handle, groupKey, helperIdx, uint16(p.Threshold), p.Target, mr)
	stepUp, err := p.StepUp(ctx, ReshareApproval{
		ContextHex: hex.EncodeToString(rc), PolicyVersion: helpers[0].pv, GroupKey: groupKey,
		Helpers: helperIdx, Threshold: uint16(p.Threshold), Vaults: p.Target,
		TargetMrenclave: strings.ToLower(p.TargetMrenclave),
	})
	if err != nil {
		abort()
		return nil, fmt.Errorf("owner approval: %w", err)
	}
	homeTok.set(stepUp)
	deals := map[uint16]*struct {
		Commitment [][]byte
		Sealed     map[uint16][]byte
	}{}
	for _, h := range helpers {
		resp, err := h.c.call(ctx, vaultRequest{FrostReshareDeal: &frostReshareDealReq{
			Session: session, Handle: p.Handle, Helpers: helperIdx, Threshold: uint16(p.Threshold),
			Vaults: p.Target, TargetMrenclave: p.TargetMrenclave, Targets: tmsg,
		}})
		if err == nil && resp.FrostReshareDealt == nil {
			err = ErrUnexpectedResponse
		}
		if err != nil {
			abort()
			return nil, fmt.Errorf("old vault %s (participant %d): %w", h.ep, h.info.Index, err)
		}
		deals[h.info.Index] = &struct {
			Commitment [][]byte
			Sealed     map[uint16][]byte
		}{resp.FrostReshareDealt.Commitment, resp.FrostReshareDealt.Sealed}
	}
	homeTok.set(p.HomeToken)

	// The new vaults, round 2: each derives its share and confirms.
	confirmations := make(map[uint16]map[uint16][]byte, n)
	for i, c := range targets {
		me := uint16(i + 1)
		mine := make(map[uint16]frostDealMessage, len(deals))
		for hi, d := range deals {
			cs := make([]string, len(d.Commitment))
			for k, cm := range d.Commitment {
				cs[k] = b64(cm)
			}
			mine[hi] = frostDealMessage{CommitmentB64: cs, SealedB64: b64(d.Sealed[me])}
		}
		resp, err := c.call(ctx, vaultRequest{FrostReshareTarget2: &frostReshareTarget2Req{
			Session: session, Handle: p.Handle, Targets: tmsg, Deals: mine,
		}})
		if err == nil && resp.FrostDkgConfirm == nil {
			err = ErrUnexpectedResponse
		}
		if err != nil {
			abort()
			return nil, fmt.Errorf("new vault %s: %w", p.Target[i], err)
		}
		if string(resp.FrostDkgConfirm.PublicKey) != string(groupKey) {
			abort()
			return nil, fmt.Errorf("new vault %s derived another public key", p.Target[i])
		}
		confirmations[me] = resp.FrostDkgConfirm.Confirmations
	}

	// Commit everywhere; undo on a failure part-way.
	var committed []*Client
	var expiresAt uint64
	for i, c := range targets {
		me := uint16(i + 1)
		mine := make(map[uint16][]byte, n-1)
		for from, conf := range confirmations {
			if from != me {
				mine[from] = conf[me]
			}
		}
		resp, err := c.call(ctx, vaultRequest{FrostReshareCommit: &frostDkgCommitReq{
			Session: session, Handle: p.Handle, ConfirmationsB64: b64Map(mine),
		}})
		if err == nil && resp.ThresholdKeyCreated == nil {
			err = ErrUnexpectedResponse
		}
		if err != nil {
			abort()
			undo := "rolled back"
			for _, cc := range committed {
				if p.InPlace {
					_, _ = cc.call(ctx, vaultRequest{FrostReshareRollback: &handleReq{Handle: p.Handle}})
				} else if aerr := cc.abortPending(ctx, "reshare", session, p.Handle); aerr != nil {
					// The session undoes a pending copy with no tombstone, so
					// a retry can use the same handle (formats §9.3.1).
					undo = "partly undone: delete the new copies"
				}
			}
			return nil, fmt.Errorf("commit on new vault %s: %w; the %d vault(s) that committed were %s",
				p.Target[i], err, len(committed), undo)
		}
		committed = append(committed, c)
		if expiresAt == 0 || resp.ThresholdKeyCreated.ExpiresAt < expiresAt {
			expiresAt = resp.ThresholdKeyCreated.ExpiresAt
		}
	}

	// Done: drop what the key leaves behind.
	if p.InPlace {
		for _, c := range targets {
			_, _ = c.call(ctx, vaultRequest{FrostReshareFinalize: &handleReq{Handle: p.Handle}})
		}
	} else {
		for _, ep := range p.Home {
			c, err := Dial(ctx, VaultRegistration{ID: ep, Endpoint: ep, Status: "static"}, homeOpts)
			if err == nil {
				_ = c.DeleteKey(ctx, p.Handle)
				c.Close()
			}
		}
	}
	return &ThresholdKey{Handle: p.Handle, PublicKey: groupKey, Threshold: p.Threshold,
		Vaults: p.Target, ExpiresAt: expiresAt}, nil
}

// groupKeyFromInfo reads the key's 32-byte public key from a vault.
func groupKeyFromInfo(c *Client, ctx context.Context, handle string) ([]byte, error) {
	ki, err := c.GetKeyInfo(ctx, handle)
	if err != nil {
		return nil, err
	}
	if len(ki.PublicKey) != 32 {
		return nil, errors.New("the vault returned no Ed25519 public key")
	}
	return ki.PublicKey, nil
}
