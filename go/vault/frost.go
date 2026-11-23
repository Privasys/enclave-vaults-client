// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

// Threshold Ed25519 keys (FROST, RFC 9591).
//
// The client orchestrates, as for Shamir secrets: it calls each vault
// directly with its own credentials and relays the vaults' messages between
// them. Every message is opaque here. The secret ones (DKG round 2) are
// sealed by one vault for another under keys the vaults attested to each
// other, so this client never sees enough to rebuild the key. Signing
// commitments and shares are public.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ----------------------------------------------------------------------
//  Wire
// ----------------------------------------------------------------------

type frostRound1Message struct {
	PackageB64  string `json:"package_b64"`
	DhPublicB64 string `json:"dh_public_b64"`
	QuoteB64    string `json:"quote_b64"`
}

type frostDkgRound1Req struct {
	Session   string   `json:"session"`
	Handle    string   `json:"handle"`
	Grant     string   `json:"grant"`
	Index     uint16   `json:"index"`
	Threshold uint16   `json:"threshold"`
	Vaults    []string `json:"vaults"`
}

type frostDkgRound2Req struct {
	Session string                        `json:"session"`
	Handle  string                        `json:"handle"`
	Round1  map[uint16]frostRound1Message `json:"round1"`
}

type frostDkgRound3Req struct {
	Session     string            `json:"session"`
	Handle      string            `json:"handle"`
	PackagesB64 map[uint16]string `json:"packages_b64"`
}

type frostDkgCommitReq struct {
	Session          string            `json:"session"`
	Handle           string            `json:"handle"`
	ConfirmationsB64 map[uint16]string `json:"confirmations_b64"`
}

type frostSessionReq struct {
	Session string `json:"session"`
}

type frostSignRound1Req struct {
	Session    string          `json:"session"`
	Handle     string          `json:"handle"`
	MessageB64 string          `json:"message_b64"`
	Approvals  []ApprovalToken `json:"approvals,omitempty"`
}

type frostSignRound2Req struct {
	Session        string            `json:"session"`
	Handle         string            `json:"handle"`
	CommitmentsB64 map[uint16]string `json:"commitments_b64"`
}

type frostAggregateReq struct {
	Handle         string            `json:"handle"`
	MessageB64     string            `json:"message_b64"`
	CommitmentsB64 map[uint16]string `json:"commitments_b64"`
	SharesB64      map[uint16]string `json:"shares_b64"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64Map(m map[uint16][]byte) map[uint16]string {
	out := make(map[uint16]string, len(m))
	for k, v := range m {
		out[k] = b64(v)
	}
	return out
}

// NewFrostSession returns a fresh random session id.
func NewFrostSession() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ----------------------------------------------------------------------
//  One vault
// ----------------------------------------------------------------------

// FrostRound1 is a vault's DKG round 1 message.
type FrostRound1 struct {
	Package, DhPublic, Quote []byte
}

// FrostDkgRound1 starts a DKG on this vault as participant index (1-based)
// of vaults. grant is a key-creation grant for FrostEd25519, not exportable.
func (c *Client) FrostDkgRound1(ctx context.Context, session, handle, grant string,
	index, threshold int, vaults []string) (*FrostRound1, error) {
	resp, err := c.call(ctx, vaultRequest{FrostDkgRound1: &frostDkgRound1Req{
		Session: session, Handle: handle, Grant: grant,
		Index: uint16(index), Threshold: uint16(threshold), Vaults: vaults,
	}})
	if err != nil {
		return nil, err
	}
	if resp.FrostDkgRound1 == nil {
		return nil, ErrUnexpectedResponse
	}
	r := resp.FrostDkgRound1
	return &FrostRound1{Package: r.Package, DhPublic: r.DhPublic, Quote: r.Quote}, nil
}

// FrostDkgRound2 hands the vault every participant's round 1 message and
// returns its sealed round 2 package for each other participant.
func (c *Client) FrostDkgRound2(ctx context.Context, session, handle string,
	round1 map[uint16]*FrostRound1) (map[uint16][]byte, error) {
	wire := make(map[uint16]frostRound1Message, len(round1))
	for i, m := range round1 {
		wire[i] = frostRound1Message{PackageB64: b64(m.Package), DhPublicB64: b64(m.DhPublic), QuoteB64: b64(m.Quote)}
	}
	resp, err := c.call(ctx, vaultRequest{FrostDkgRound2: &frostDkgRound2Req{
		Session: session, Handle: handle, Round1: wire,
	}})
	if err != nil {
		return nil, err
	}
	if resp.FrostDkgSealed == nil {
		return nil, ErrUnexpectedResponse
	}
	return resp.FrostDkgSealed.Packages, nil
}

// FrostDkgRound3 hands the vault the sealed packages addressed to it (by
// sender) and returns the group key it derived and its confirmation for each
// other participant.
func (c *Client) FrostDkgRound3(ctx context.Context, session, handle string,
	packages map[uint16][]byte) (publicKey []byte, confirmations map[uint16][]byte, err error) {
	resp, err := c.call(ctx, vaultRequest{FrostDkgRound3: &frostDkgRound3Req{
		Session: session, Handle: handle, PackagesB64: b64Map(packages),
	}})
	if err != nil {
		return nil, nil, err
	}
	if resp.FrostDkgConfirm == nil {
		return nil, nil, ErrUnexpectedResponse
	}
	return resp.FrostDkgConfirm.PublicKey, resp.FrostDkgConfirm.Confirmations, nil
}

// FrostDkgCommit hands the vault the other participants' confirmations for
// it; the vault stores its share only if they all check out.
func (c *Client) FrostDkgCommit(ctx context.Context, session, handle string,
	confirmations map[uint16][]byte) (publicKey []byte, expiresAt uint64, err error) {
	resp, err := c.call(ctx, vaultRequest{FrostDkgCommit: &frostDkgCommitReq{
		Session: session, Handle: handle, ConfirmationsB64: b64Map(confirmations),
	}})
	if err != nil {
		return nil, 0, err
	}
	if resp.ThresholdKeyCreated == nil {
		return nil, 0, ErrUnexpectedResponse
	}
	return resp.ThresholdKeyCreated.PublicKey, resp.ThresholdKeyCreated.ExpiresAt, nil
}

// FrostDkgAbort drops a DKG session on this vault.
func (c *Client) FrostDkgAbort(ctx context.Context, session string) error {
	_, err := c.call(ctx, vaultRequest{FrostDkgAbort: &frostSessionReq{Session: session}})
	return err
}

// FrostSignRound1 asks the vault to take part in a signature: authorised
// like Sign (the key's policy, this client's credentials, approvals).
// Returns the vault's participant index and its commitment.
func (c *Client) FrostSignRound1(ctx context.Context, session, handle string, message []byte,
	approvals ...ApprovalToken) (index uint16, commitment []byte, err error) {
	resp, err := c.call(ctx, vaultRequest{FrostSignRound1: &frostSignRound1Req{
		Session: session, Handle: handle, MessageB64: b64(message), Approvals: approvals,
	}})
	if err != nil {
		return 0, nil, err
	}
	if resp.FrostCommitment == nil {
		return 0, nil, ErrUnexpectedResponse
	}
	return resp.FrostCommitment.Index, resp.FrostCommitment.Commitment, nil
}

// FrostSignRound2 hands the vault every signer's commitment and returns its
// signature share.
func (c *Client) FrostSignRound2(ctx context.Context, session, handle string,
	commitments map[uint16][]byte) ([]byte, error) {
	resp, err := c.call(ctx, vaultRequest{FrostSignRound2: &frostSignRound2Req{
		Session: session, Handle: handle, CommitmentsB64: b64Map(commitments),
	}})
	if err != nil {
		return nil, err
	}
	if resp.FrostSignatureShare == nil {
		return nil, ErrUnexpectedResponse
	}
	return resp.FrostSignatureShare.Share, nil
}

// FrostSignAbort drops a signing session on this vault.
func (c *Client) FrostSignAbort(ctx context.Context, session string) error {
	_, err := c.call(ctx, vaultRequest{FrostSignAbort: &frostSessionReq{Session: session}})
	return err
}

// FrostAggregate combines the shares into the Ed25519 signature, verified
// by the vault under the group key.
func (c *Client) FrostAggregate(ctx context.Context, handle string, message []byte,
	commitments, shares map[uint16][]byte) ([]byte, string, error) {
	resp, err := c.call(ctx, vaultRequest{FrostAggregate: &frostAggregateReq{
		Handle: handle, MessageB64: b64(message),
		CommitmentsB64: b64Map(commitments), SharesB64: b64Map(shares),
	}})
	if err != nil {
		return nil, "", err
	}
	if resp.Signature == nil {
		return nil, "", ErrUnexpectedResponse
	}
	return resp.Signature.Signature, resp.Signature.Alg, nil
}

// ----------------------------------------------------------------------
//  The constellation
// ----------------------------------------------------------------------

// ThresholdKey describes a threshold key every participant stored.
type ThresholdKey struct {
	Handle string
	// PublicKey is the 32-byte Ed25519 group key.
	PublicKey []byte
	Threshold int
	// Vaults lists the participants' endpoints, participant i at Vaults[i-1].
	Vaults    []string
	ExpiresAt uint64
}

// dialAll opens one connection per vault, kept for every round: a vault
// binds a session to the caller that opened it.
func (con *Constellation) dialAll(ctx context.Context) ([]VaultRegistration, []*Client, error) {
	vaults, err := con.listVaults(ctx)
	if err != nil {
		return nil, nil, err
	}
	clients := make([]*Client, len(vaults))
	for i, v := range vaults {
		c, err := Dial(ctx, v, con.Dial)
		if err != nil {
			closeAll(clients)
			return nil, nil, fmt.Errorf("vault %s: %w", v.Endpoint, err)
		}
		clients[i] = c
	}
	return vaults, clients, nil
}

func closeAll(clients []*Client) {
	for _, c := range clients {
		if c != nil {
			c.Close()
		}
	}
}

// CreateThresholdKey creates a threshold Ed25519 key across every vault of
// the constellation by distributed key generation: no vault, and not this
// client, ever holds the key. Any threshold of the vaults can sign. grant is
// a key-creation grant for FrostEd25519, not exportable, bound to this
// client as for CreateKey.
func (con *Constellation) CreateThresholdKey(ctx context.Context, handle, grant string,
	threshold int) (*ThresholdKey, error) {
	vaults, clients, err := con.dialAll(ctx)
	if err != nil {
		return nil, err
	}
	defer closeAll(clients)
	n := len(clients)
	if threshold < 2 || threshold > n {
		return nil, fmt.Errorf("threshold must be 2..%d (the constellation has %d vaults), got %d", n, n, threshold)
	}
	endpoints := make([]string, n)
	for i, v := range vaults {
		endpoints[i] = v.Endpoint
	}
	session, err := NewFrostSession()
	if err != nil {
		return nil, err
	}
	stored := 0
	fail := func(round string, i int, err error) (*ThresholdKey, error) {
		for _, c := range clients {
			_ = c.FrostDkgAbort(ctx, session)
		}
		msg := fmt.Sprintf("%s on vault %s: %v", round, endpoints[i], err)
		if stored > 0 {
			msg += fmt.Sprintf("; the key was stored on %d of %d vaults: delete it and create it again", stored, n)
		}
		return nil, errors.New(msg)
	}

	round1 := make(map[uint16]*FrostRound1, n)
	for i, c := range clients {
		m, err := c.FrostDkgRound1(ctx, session, handle, grant, i+1, threshold, endpoints)
		if err != nil {
			return fail("DKG round 1", i, err)
		}
		round1[uint16(i+1)] = m
	}

	// sealed[from][to]
	sealed := make(map[uint16]map[uint16][]byte, n)
	for i, c := range clients {
		out, err := c.FrostDkgRound2(ctx, session, handle, round1)
		if err != nil {
			return fail("DKG round 2", i, err)
		}
		sealed[uint16(i+1)] = out
	}

	confirmations := make(map[uint16]map[uint16][]byte, n)
	var groupKey []byte
	for i, c := range clients {
		me := uint16(i + 1)
		mine := make(map[uint16][]byte, n-1)
		for from, out := range sealed {
			if from != me {
				mine[from] = out[me]
			}
		}
		pk, conf, err := c.FrostDkgRound3(ctx, session, handle, mine)
		if err != nil {
			return fail("DKG round 3", i, err)
		}
		if groupKey == nil {
			groupKey = pk
		} else if string(groupKey) != string(pk) {
			return fail("DKG round 3", i, errors.New("the vaults derived different group keys"))
		}
		confirmations[me] = conf
	}

	var expiresAt uint64
	for i, c := range clients {
		me := uint16(i + 1)
		mine := make(map[uint16][]byte, n-1)
		for from, conf := range confirmations {
			if from != me {
				mine[from] = conf[me]
			}
		}
		_, exp, err := c.FrostDkgCommit(ctx, session, handle, mine)
		if err != nil {
			return fail("DKG commit", i, err)
		}
		stored++
		if expiresAt == 0 || exp < expiresAt {
			expiresAt = exp
		}
	}
	return &ThresholdKey{Handle: handle, PublicKey: groupKey, Threshold: threshold,
		Vaults: endpoints, ExpiresAt: expiresAt}, nil
}

// SignThreshold signs message with a threshold key: round 1 on the vaults
// (each checks the key's policy against this client's own credentials and
// approvals), round 2 on those that agreed, then one of them aggregates and
// verifies the signature. threshold > 0 stops round 1 once that many vaults
// agreed; 0 asks every vault (FROST accepts any number of signers from the
// key's threshold up to its participants, and each vault enforces that).
// Returns the 64-byte Ed25519 signature and its algorithm ("EdDSA").
func (con *Constellation) SignThreshold(ctx context.Context, handle string, message []byte,
	threshold int, approvals ...ApprovalToken) ([]byte, string, error) {
	vaults, err := con.listVaults(ctx)
	if err != nil {
		return nil, "", err
	}
	session, err := NewFrostSession()
	if err != nil {
		return nil, "", err
	}
	signers := map[uint16]*Client{}
	commitments := map[uint16][]byte{}
	var failures []string
	defer func() {
		for _, c := range signers {
			c.Close()
		}
	}()
	for _, v := range vaults {
		if threshold > 0 && len(signers) >= threshold {
			break
		}
		c, err := Dial(ctx, v, con.Dial)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", v.Endpoint, err))
			continue
		}
		idx, commitment, err := c.FrostSignRound1(ctx, session, handle, message, approvals...)
		if err != nil {
			c.Close()
			failures = append(failures, fmt.Sprintf("%s: %v", v.Endpoint, err))
			continue
		}
		if _, dup := commitments[idx]; dup {
			_ = c.FrostSignAbort(ctx, session)
			c.Close()
			continue
		}
		signers[idx] = c
		commitments[idx] = commitment
	}
	abort := func() {
		for _, c := range signers {
			_ = c.FrostSignAbort(ctx, session)
		}
	}
	need := threshold
	if need < 2 {
		need = 2
	}
	if len(signers) < need {
		abort()
		return nil, "", fmt.Errorf("only %d vault(s) agreed to sign: %s",
			len(signers), strings.Join(failures, "; "))
	}
	shares := map[uint16][]byte{}
	for idx, c := range signers {
		s, err := c.FrostSignRound2(ctx, session, handle, commitments)
		if err != nil {
			abort()
			return nil, "", fmt.Errorf("signing round 2 on participant %d: %w", idx, err)
		}
		shares[idx] = s
	}
	for _, c := range signers {
		return c.FrostAggregate(ctx, handle, message, commitments, shares)
	}
	return nil, "", errors.New("no signer")
}
