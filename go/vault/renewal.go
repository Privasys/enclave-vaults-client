// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

// Renewal of a key by the app that holds it: in place on the same vault, or
// onto another constellation with the policy read fresh from the source
// vault and carried verbatim; and the retirement of the previous generation
// afterwards. See docs/vault.md in https://github.com/Privasys/enclave-os-mini.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ErrUnsupported reports a vault that does not know the request: a vault
// build that predates a request answers it by echoing it back.
var ErrUnsupported = errors.New("vault: request not supported by this vault build")

// IsUnsupported reports whether err means the vault does not know the request.
func IsUnsupported(err error) bool { return errors.Is(err, ErrUnsupported) }

// KeyCheck is the key check value of a whole key: an Argon2id digest under a
// random salt, which the vault stores opaquely and never returns.
type KeyCheck struct {
	SaltB64   string `json:"salt_b64"`
	DigestHex string `json:"digest_hex"`
}

// Argon2id parameters of the key check value.
const (
	keyCheckTime    = 3
	keyCheckMemory  = 64 * 1024 // KiB: 64 MiB
	keyCheckThreads = 1
	keyCheckLen     = 32
	keyCheckDomain  = "privasys-key-check-v1"
)

// NewKeyCheck computes the key check value of the WHOLE key (not a share)
// under a fresh random salt: Argon2id(password = key, salt = domain || salt).
func NewKeyCheck(key []byte) (KeyCheck, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return KeyCheck{}, fmt.Errorf("key check salt: %w", err)
	}
	return keyCheckWithSalt(key, salt), nil
}

func keyCheckWithSalt(key, salt []byte) KeyCheck {
	s := append([]byte(keyCheckDomain), salt...)
	d := argon2.IDKey(key, s, keyCheckTime, keyCheckMemory, keyCheckThreads, keyCheckLen)
	return KeyCheck{
		SaltB64:   base64.RawURLEncoding.EncodeToString(salt),
		DigestHex: hex.EncodeToString(d),
	}
}

// Renewal says where a new generation's policy comes from.
//
//   - In place: Predecessor is the old handle on this same vault; Policy is
//     nil. The vault copies the predecessor's policy, version and key check.
//   - Move or rotation: Policy is the key's current policy as GetPolicyRaw
//     returned it from the source vault, carried verbatim, with its
//     PolicyVersion and the source's billing id. Predecessor names the old
//     handle for the audit log, or is empty for a rotation.
type Renewal struct {
	Predecessor     string
	Policy          json.RawMessage
	PolicyVersion   uint32
	SourceBillingID string
	KeyCheck        *KeyCheck // fresh for a move, rotation or creation; nil in place
	// With a carried Policy: the source key's exportable flag and type, as
	// GetKeyInfo reported them on every source vault. The target refuses a
	// grant that differs (a carried key keeps both).
	CarriedExportable *bool
	CarriedKeyType    KeyType
}

// CapabilityGenerations is listed in VaultIdentity.Capabilities by a vault
// build that reports KeyInfo.RenewedInPlaceFrom, refuses a first creation of a
// generation handle (last segment "gen-<n>"), and keeps a carried key's
// exportable flag and type. Trust a generation link only from
// such a build, over a connection pinned to it.
const CapabilityGenerations = "generations-v1"

type renewalCreateKeyReq struct {
	Handle            string          `json:"handle"`
	MaterialB64       string          `json:"material_b64"`
	Grant             string          `json:"grant"`
	Predecessor       string          `json:"predecessor,omitempty"`
	Policy            json.RawMessage `json:"policy,omitempty"`
	PolicyVersion     uint32          `json:"policy_version,omitempty"`
	SourceBillingID   string          `json:"source_billing_id,omitempty"`
	KeyCheck          *KeyCheck       `json:"key_check,omitempty"`
	CarriedExportable *bool           `json:"carried_exportable,omitempty"`
	CarriedKeyType    KeyType         `json:"carried_key_type,omitempty"`
}

// CreateKeyRenewal creates the next generation of a key under handle, with
// material (this vault's share), the admission grant, and the renewal r.
func (c *Client) CreateKeyRenewal(ctx context.Context, handle string, material []byte,
	grant string, r Renewal) (uint64, error) {
	if r.Predecessor == "" && len(r.Policy) == 0 {
		return 0, errors.New("vault: a renewal needs a predecessor (in place) or a carried policy")
	}
	if len(r.Policy) != 0 && r.SourceBillingID == "" {
		return 0, errors.New("vault: a carried policy needs the source billing id")
	}
	if len(r.Policy) != 0 && (r.CarriedExportable == nil || r.CarriedKeyType == "") {
		return 0, errors.New("vault: a carried policy needs the source key's exportable flag and type")
	}
	req := renewalCreateKeyReq{
		Handle:            handle,
		MaterialB64:       base64.RawURLEncoding.EncodeToString(material),
		Grant:             grant,
		Predecessor:       r.Predecessor,
		Policy:            r.Policy,
		PolicyVersion:     r.PolicyVersion,
		SourceBillingID:   r.SourceBillingID,
		KeyCheck:          r.KeyCheck,
		CarriedExportable: r.CarriedExportable,
		CarriedKeyType:    r.CarriedKeyType,
	}
	body, err := json.Marshal(map[string]any{"CreateKey": req})
	if err != nil {
		return 0, fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.callRaw(ctx, body)
	if err != nil {
		return 0, err
	}
	if resp.KeyCreated == nil {
		return 0, ErrUnexpectedResponse
	}
	return resp.KeyCreated.ExpiresAt, nil
}

// GetPolicyRaw returns a key's policy exactly as the vault serialised it,
// with its version, so a renewal can carry it without dropping fields the
// typed KeyPolicy does not know.
func (c *Client) GetPolicyRaw(ctx context.Context, handle string) (json.RawMessage, uint32, error) {
	body, err := json.Marshal(map[string]any{"GetPolicy": handleReq{Handle: handle}})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal request: %w", err)
	}
	raw, err := c.sendRaw(ctx, body)
	if err != nil {
		return nil, 0, err
	}
	var env struct {
		Policy *struct {
			Policy        json.RawMessage `json:"policy"`
			PolicyVersion uint32          `json:"policy_version"`
		} `json:"Policy"`
		Error *string `json:"Error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, 0, fmt.Errorf("decode response: %w", err)
	}
	if env.Error != nil {
		return nil, 0, &ErrVaultError{Message: *env.Error}
	}
	if env.Policy == nil || len(env.Policy.Policy) == 0 {
		return nil, 0, ErrUnexpectedResponse
	}
	return env.Policy.Policy, env.Policy.PolicyVersion, nil
}

type retireKeyReq struct {
	Handle           string   `json:"handle"`
	Successor        string   `json:"successor"`
	SuccessorMembers []string `json:"successor_members"`
}

// RetireKey deletes the previous generation of a key after an automatic
// renewal. The caller must be an enclave the key's policy
// names. successorMembers are the sorted member ids of the vaults holding the
// successor. wasPresent is false when the key was already gone.
func (c *Client) RetireKey(ctx context.Context, handle, successor string,
	successorMembers []string) (bool, error) {
	body, err := json.Marshal(map[string]any{"RetireKey": retireKeyReq{
		Handle:           handle,
		Successor:        successor,
		SuccessorMembers: successorMembers,
	}})
	if err != nil {
		return false, fmt.Errorf("marshal request: %w", err)
	}
	raw, err := c.sendRaw(ctx, body)
	if err != nil {
		return false, err
	}
	var env struct {
		KeyRetired *struct {
			WasPresent bool `json:"was_present"`
		} `json:"KeyRetired"`
		Error *string `json:"Error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}
	if env.Error != nil {
		return false, &ErrVaultError{Message: *env.Error}
	}
	if env.KeyRetired == nil {
		return false, ErrUnexpectedResponse
	}
	return env.KeyRetired.WasPresent, nil
}

// sendRaw sends a pre-marshalled request and returns the raw response body.
// A vault that does not know the request echoes it back unchanged (the
// runtime's fallback for unhandled data): that is ErrUnsupported.
func (c *Client) sendRaw(ctx context.Context, payload []byte) ([]byte, error) {
	var token string
	var err error
	if c.opts.AuthToken != nil {
		token, err = c.opts.AuthToken.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("auth token: %w", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		if err := c.reconnect(ctx); err != nil {
			return nil, err
		}
	}
	body, err := c.conn.SendData(payload, token)
	if err != nil {
		// Retry once on connection error.
		_ = c.conn.Close()
		c.conn = nil
		if err2 := c.reconnect(ctx); err2 != nil {
			return nil, fmt.Errorf("send (retry dial): %w", err2)
		}
		body, err = c.conn.SendData(payload, token)
		if err != nil {
			return nil, fmt.Errorf("send: %w", err)
		}
	}
	if bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(payload)) {
		return nil, ErrUnsupported
	}
	return body, nil
}

// callRaw sends a pre-marshalled request and decodes the typed response.
func (c *Client) callRaw(ctx context.Context, payload []byte) (*vaultResponse, error) {
	body, err := c.sendRaw(ctx, payload)
	if err != nil {
		return nil, err
	}
	resp, err := unmarshalResponse(body)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w; raw=%s", err, truncate(body, 256))
	}
	return resp, resp.errorOr()
}

// CanonicalisePolicy asks the vault for its verdict on a policy without
// storing anything: the digest it would bind, or its refusal (a
// field it does not know, a value its normalisation would change). A binding
// v2 client calls it before asking the owner to approve a policy, so a policy
// the vault would refuse fails before the tap, not after. Unauthenticated.
func (c *Client) CanonicalisePolicy(ctx context.Context, policy json.RawMessage) (string, error) {
	_, pd, err := c.CanonicalPolicy(ctx, policy)
	return pd, err
}

// CanonicalPolicy is CanonicalisePolicy returning also the policy as the vault
// would store it, every field written (as GetPolicy returns a stored one). A
// client that rebuilt a policy from a typed form compares this with the stored
// policy to know nothing was dropped: the typed form may leave out fields at
// their default, which the vault writes back.
func (c *Client) CanonicalPolicy(ctx context.Context, policy json.RawMessage) (json.RawMessage, string, error) {
	if !json.Valid(policy) {
		return nil, "", errors.New("canonicalise policy: not valid JSON")
	}
	body, err := json.Marshal(map[string]any{"CanonicalisePolicy": map[string]json.RawMessage{"policy": policy}})
	if err != nil {
		return nil, "", fmt.Errorf("marshal request: %w", err)
	}
	raw, err := c.sendRaw(ctx, body)
	if err != nil {
		return nil, "", err
	}
	var env struct {
		CanonicalPolicy *struct {
			Policy json.RawMessage `json:"policy"`
			PD     string          `json:"pd"`
		} `json:"CanonicalPolicy"`
		Error *string `json:"Error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, "", fmt.Errorf("decode response: %w", err)
	}
	if env.Error != nil {
		return nil, "", &ErrVaultError{Message: *env.Error}
	}
	if env.CanonicalPolicy == nil || env.CanonicalPolicy.PD == "" || len(env.CanonicalPolicy.Policy) == 0 {
		return nil, "", ErrUnexpectedResponse
	}
	return env.CanonicalPolicy.Policy, env.CanonicalPolicy.PD, nil
}
