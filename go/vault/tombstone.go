package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// CapabilityTombstones is advertised by a vault that keeps tombstones
// (formats §9.3): a deleted key answers "key deleted" to its principals and
// its handle cannot be created again until the key's original expiry; a
// re-created name (".../new-<k>") needs its owner's bound create approval
// and GetKeyInfo reports CreatedByOwnerApproval; a threshold key committed by
// a session that then failed is aborted through that session (§9.3.1).
const CapabilityTombstones = "tombstones-v1"

// KeyTombstone is what GetKeyInfo returns, to the principals of a deleted
// key's final policy, instead of its info.
type KeyTombstone struct {
	Handle    string  `json:"handle"`
	KeyType   KeyType `json:"key_type"`
	Op        string  `json:"op"` // "delete", "delete_after" or "retire"
	DeletedAt uint64  `json:"deleted_at"`
	Successor string  `json:"successor"`  // a handle, or "-"
	ExpiresAt uint64  `json:"expires_at"` // the handle is reusable after this
}

// ErrKeyDeleted is returned by GetKeyInfo for a deleted key. Every other
// operation on it fails with an ErrVaultError whose message starts with
// "key deleted"; IsKeyDeleted recognises both.
type ErrKeyDeleted struct{ Tombstone KeyTombstone }

func (e *ErrKeyDeleted) Error() string {
	return fmt.Sprintf("key deleted at %d (%s); successor %s; the handle is reusable after %d",
		e.Tombstone.DeletedAt, e.Tombstone.Op, e.Tombstone.Successor, e.Tombstone.ExpiresAt)
}

// IsKeyDeleted reports whether err says the key was deleted (a tombstone),
// as opposed to never having existed ("key not found") or being out of the
// caller's reach. Only the key's principals are ever told this.
func IsKeyDeleted(err error) bool {
	var kd *ErrKeyDeleted
	if errors.As(err, &kd) {
		return true
	}
	var ve *ErrVaultError
	return errors.As(err, &ve) && strings.HasPrefix(ve.Message, "key deleted")
}

// IsHandleTombstoned reports whether a create failed because the handle was
// deleted and is held until its original expiry.
func IsHandleTombstoned(err error) bool {
	var ve *ErrVaultError
	return errors.As(err, &ve) && strings.HasPrefix(ve.Message, "handle deleted at")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isNewSegment(seg string) bool {
	n, ok := strings.CutPrefix(seg, "new-")
	return ok && isDigits(n)
}

// IsReCreatedName reports whether handle's last segment is "new-<digits>":
// a name re-created after a delete (formats §9.3.1). The vault creates it
// only with the owner's bound create approval.
func IsReCreatedName(handle string) bool {
	segs := strings.Split(handle, "/")
	return isNewSegment(segs[len(segs)-1])
}

// IsBeneathReCreatedName reports whether handle lies under a "new-<digits>"
// segment (not its last one). Only a linked renewal ending in "gen-<m>" may
// be created there.
func IsBeneathReCreatedName(handle string) bool {
	segs := strings.Split(handle, "/")
	for _, s := range segs[:len(segs)-1] {
		if isNewSegment(s) {
			return true
		}
	}
	return false
}

// ReCreatedName is the handle of the k-th re-creation of base (k >= 2):
// "<base>/new-<k>".
func ReCreatedName(base string, k int) (string, error) {
	if k < 2 {
		return "", fmt.Errorf("a re-created name starts at new-2, got %d", k)
	}
	return fmt.Sprintf("%s/new-%d", base, k), nil
}

// createBinding is the binding a creation carries: the members, for a
// re-created name only (the approval itself is the bearer, the owner's
// step-up for op "create", target PD of the stored policy, version 0).
func (c *Client) createBinding(handle string) *bindingMembers {
	if !IsReCreatedName(handle) {
		return nil
	}
	return c.bindingMembers()
}

// abortPending undoes a threshold key a session committed on this vault and
// that has served nothing yet (formats §9.3.1): within the session's time,
// by the same caller. No tombstone is left.
func (c *Client) abortPending(ctx context.Context, kind, session, handle string) error {
	req := &frostSessionReq{Session: session, Handle: handle}
	var vr vaultRequest
	if kind == "reshare" {
		vr.FrostReshareAbort = req
	} else {
		vr.FrostDkgAbort = req
	}
	_, err := c.call(ctx, vr)
	return err
}
