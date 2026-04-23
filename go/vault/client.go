// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

// Enclave Vaults Go client (constellation-aware, HSM-shaped wire protocol).
//
// Compatible with `enclave-os-mini >= v0.19` and the Privasys
// `enclave-vaults` composition crate. Replaces the legacy
// StoreSecret/GetSecret/DeleteSecret/UpdateSecretPolicy API.
//
// Three layers of API:
//
//  1. Registry discovery â€” query the Attested Registry phonebook to find
//     live vault instances:
//
//         reg := NewRegistryClient("https://u.registry.vaults.privasys.org")
//         vaults, _ := reg.ListVaults(ctx)
//
//  2. Single-vault key operations â€” connect to one vault over RA-TLS and
//     issue HSM-shaped requests (CreateKey / Wrap / Sign / etc.):
//
//         c, _ := Dial(ctx, vaults[0], DialOptions{
//             AuthToken:           bearerProvider,
//             VaultPolicy:         policy,
//             GetClientCertificate: ratlsClientCert,
//         })
//         defer c.Close()
//         _, err := c.CreateKey(ctx, "my-aes-key", Aes256GcmKey, keyBytes,
//             false, KeyPolicy{...})
//
//  3. Constellation fan-out â€” for operations that must succeed on every
//     vault holding the same logical key (in particular: pending
//     attestation profiles for an enclave upgrade):
//
//         con := NewConstellation(reg, dialOpts)
//         results, _ := con.StagePendingProfile(ctx, "my-key", profile, PlatformBuild)
//
// Shamir Secret Sharing helpers (shamir.go) are unchanged and used to
// split a secret into RawShare key material before CreateKey.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"enclave-os-mini/clients/go/ratls"
)

// ===========================================================================
//  Errors
// ===========================================================================

// ErrVaultError is returned when the vault rejects a request with a
// VaultResponse::Error variant. The wrapped string is the vault's
// human-readable reason.
type ErrVaultError struct{ Message string }

func (e *ErrVaultError) Error() string { return "vault error: " + e.Message }

// ErrUnexpectedResponse means the vault returned a response variant
// that did not match the requested operation.
var ErrUnexpectedResponse = errors.New("vault: unexpected response variant")

// ===========================================================================
//  Registry client
// ===========================================================================

// VaultRegistration mirrors the registry's JSON shape (see
// platform/enclave-vaults/registry/main.go).
type VaultRegistration struct {
	ID            string    `json:"id"`
	Endpoint      string    `json:"endpoint"`
	MREnclave     string    `json:"mrenclave"`
	MRSigner      string    `json:"mrsigner,omitempty"`
	RegisteredAt  time.Time `json:"registeredAt"`
	LastHeartbeat time.Time `json:"lastHeartbeat"`
	Status        string    `json:"status"`
}

// Host returns the host portion of Endpoint.
func (v VaultRegistration) Host() string {
	if i := strings.LastIndex(v.Endpoint, ":"); i > 0 {
		return v.Endpoint[:i]
	}
	return v.Endpoint
}

// Port returns the port portion of Endpoint, or 8443 if absent / invalid.
func (v VaultRegistration) Port() int {
	if i := strings.LastIndex(v.Endpoint, ":"); i > 0 {
		if p, err := strconv.Atoi(v.Endpoint[i+1:]); err == nil {
			return p
		}
	}
	return 8443
}

// RegistryClient is a thin client for the Attested Registry phonebook.
type RegistryClient struct {
	BaseURL string
	HTTP    *http.Client
}

// NewRegistryClient constructs a RegistryClient with a default 10s HTTP timeout.
func NewRegistryClient(baseURL string) *RegistryClient {
	return &RegistryClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// ListVaults fetches the current set of live vault registrations.
func (rc *RegistryClient) ListVaults(ctx context.Context) ([]VaultRegistration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rc.BaseURL+"/api/vaults", nil)
	if err != nil {
		return nil, err
	}
	resp, err := rc.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("registry: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Vaults []VaultRegistration `json:"vaults"`
		Count  int                 `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("registry: decode: %w", err)
	}
	return payload.Vaults, nil
}

// ===========================================================================
//  Wire types â€” VaultRequest / VaultResponse
//
//  Mirror enclave-os-mini/crates/enclave-os-vault/src/types.rs.
//  Each VaultRequest is JSON-encoded as a single-key object whose key is
//  the variant name (Rust serde default for externally-tagged enums).
// ===========================================================================

// KeyType is the cryptographic type of a stored key.
type KeyType string

const (
	RawShare       KeyType = "RawShare"
	Aes256GcmKey   KeyType = "Aes256GcmKey"
	P256SigningKey KeyType = "P256SigningKey"
	HmacSha256Key  KeyType = "HmacSha256Key"
)

// Operation is a per-key operation that can be granted by an OperationRule.
type Operation string

const (
	OpExportKey      Operation = "ExportKey"
	OpDeleteKey      Operation = "DeleteKey"
	OpUpdatePolicy   Operation = "UpdatePolicy"
	OpWrap           Operation = "Wrap"
	OpUnwrap         Operation = "Unwrap"
	OpSign           Operation = "Sign"
	OpMac            Operation = "Mac"
	OpPromoteProfile Operation = "PromoteProfile"
)

// PolicyField identifies a top-level policy field that mutability rules
// can grant or forbid changes on.
type PolicyField string

const (
	FieldOwner           PolicyField = "Owner"
	FieldManagers        PolicyField = "Managers"
	FieldAuditors        PolicyField = "Auditors"
	FieldTees            PolicyField = "Tees"
	FieldOperations      PolicyField = "Operations"
	FieldLifecycle       PolicyField = "Lifecycle"
	FieldMutability      PolicyField = "Mutability"
	FieldPendingProfiles PolicyField = "PendingProfiles"
)

// PendingProfileSource records who staged a pending attestation profile.
type PendingProfileSource string

const (
	PlatformBuild PendingProfileSource = "PlatformBuild"
	ManualImport  PendingProfileSource = "ManualImport"
)

// AuditDecision is the outcome of an audited operation.
type AuditDecision string

const (
	AuditAllowed AuditDecision = "Allowed"
	AuditDenied  AuditDecision = "Denied"
)

// ----------------------------------------------------------------------
//  Principals & attestation
// ----------------------------------------------------------------------

// Principal is an identity that can act on a key. Exactly one variant
// field must be non-nil at a time (matches Rust externally-tagged enum).
type Principal struct {
	Oidc  *OidcPrincipal      `json:"Oidc,omitempty"`
	Fido2 *Fido2Principal     `json:"Fido2,omitempty"`
	Tee   *AttestationProfile `json:"Tee,omitempty"`
}

// OidcPrincipal authenticates via an OIDC bearer token whose `iss` matches
// Issuer, whose `sub` matches Sub, and whose roles (resolved per the
// platform's OIDC config) include every entry in RequiredRoles (case-
// insensitive).
type OidcPrincipal struct {
	Issuer        string   `json:"issuer"`
	Sub           string   `json:"sub"`
	RequiredRoles []string `json:"required_roles,omitempty"`
}

// Fido2Principal authenticates via a previously-registered FIDO2
// credential. Reserved â€” not yet honoured by the vault.
type Fido2Principal struct {
	RpID            string `json:"rp_id"`
	CredentialIDB64 string `json:"credential_id_b64"`
}

// AttestationProfile constrains what a remote TEE quote must satisfy.
type AttestationProfile struct {
	Name               string              `json:"name"`
	Measurements       []Measurement       `json:"measurements"`
	AttestationServers []AttestationServer `json:"attestation_servers"`
	RequiredOIDs       []OidRequirement    `json:"required_oids,omitempty"`
}

// Measurement is one acceptable enclave/VM measurement.
type Measurement struct {
	Mrenclave string `json:"Mrenclave,omitempty"`
	Mrtd      string `json:"Mrtd,omitempty"`
}

// AttestationServer pins an attestation verifier endpoint.
type AttestationServer struct {
	URL                 string `json:"url"`
	PinnedSPKISHA256Hex string `json:"pinned_spki_sha256_hex,omitempty"`
}

// OidRequirement is a required X.509 OID extension on a peer cert.
type OidRequirement struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
}

// PrincipalSet groups the named identities of a key.
type PrincipalSet struct {
	Owner    Principal   `json:"owner"`
	Managers []Principal `json:"managers,omitempty"`
	Auditors []Principal `json:"auditors,omitempty"`
	Tees     []Principal `json:"tees,omitempty"`
}

// PrincipalRef is a reference into a PrincipalSet.
//
// On the wire it serialises as one of:
//
//	"Owner" | "AnyTee"            (unit variants)
//	{"Manager": <u32>}            (newtype variants)
//	{"Auditor": <u32>}
//	{"Tee":     <u32>}
type PrincipalRef struct {
	Owner   bool
	AnyTee  bool
	Manager *uint32
	Auditor *uint32
	Tee     *uint32
}

// MarshalJSON implements custom serde-compatible serialization.
func (p PrincipalRef) MarshalJSON() ([]byte, error) {
	switch {
	case p.Owner:
		return []byte(`"Owner"`), nil
	case p.AnyTee:
		return []byte(`"AnyTee"`), nil
	case p.Manager != nil:
		return json.Marshal(map[string]uint32{"Manager": *p.Manager})
	case p.Auditor != nil:
		return json.Marshal(map[string]uint32{"Auditor": *p.Auditor})
	case p.Tee != nil:
		return json.Marshal(map[string]uint32{"Tee": *p.Tee})
	}
	return nil, errors.New("PrincipalRef: no variant set")
}

// UnmarshalJSON implements custom serde-compatible deserialization.
func (p *PrincipalRef) UnmarshalJSON(data []byte) error {
	*p = PrincipalRef{}
	s := strings.TrimSpace(string(data))
	switch s {
	case `"Owner"`:
		p.Owner = true
		return nil
	case `"AnyTee"`:
		p.AnyTee = true
		return nil
	}
	var obj map[string]uint32
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	for k, v := range obj {
		v := v
		switch k {
		case "Manager":
			p.Manager = &v
		case "Auditor":
			p.Auditor = &v
		case "Tee":
			p.Tee = &v
		default:
			return fmt.Errorf("PrincipalRef: unknown variant %q", k)
		}
		return nil
	}
	return errors.New("PrincipalRef: empty object")
}

// Helpers for constructing PrincipalRef values.
func RefOwner() PrincipalRef           { return PrincipalRef{Owner: true} }
func RefAnyTee() PrincipalRef          { return PrincipalRef{AnyTee: true} }
func RefManager(i uint32) PrincipalRef { return PrincipalRef{Manager: &i} }
func RefAuditor(i uint32) PrincipalRef { return PrincipalRef{Auditor: &i} }
func RefTee(i uint32) PrincipalRef     { return PrincipalRef{Tee: &i} }

// Condition is an extra access-time predicate attached to an OperationRule.
//
// On the wire it serialises as one of:
//
//	{"AttestationMatches": <AttestationProfile>}
//	{"ManagerApproval":    {"manager": u32, "fresh_for_seconds": u64}}
//	{"TimeWindow":         {"not_before": u64, "not_after": u64}}
type Condition struct {
	AttestationMatches *AttestationProfile  `json:"AttestationMatches,omitempty"`
	ManagerApproval    *ManagerApprovalCond `json:"ManagerApproval,omitempty"`
	TimeWindow         *TimeWindowCond      `json:"TimeWindow,omitempty"`
}

// ManagerApprovalCond requires a fresh approval token from a manager.
type ManagerApprovalCond struct {
	Manager         uint32 `json:"manager"`
	FreshForSeconds uint64 `json:"fresh_for_seconds"`
}

// TimeWindowCond constrains the allowed wall-clock window. 0 = unbounded.
type TimeWindowCond struct {
	NotBefore uint64 `json:"not_before,omitempty"`
	NotAfter  uint64 `json:"not_after,omitempty"`
}

// OperationRule grants a set of operations to a set of principals.
type OperationRule struct {
	Ops        []Operation    `json:"ops"`
	Principals []PrincipalRef `json:"principals"`
	Requires   []Condition    `json:"requires,omitempty"`
}

// Mutability controls who can change which fields on UpdatePolicy.
type Mutability struct {
	OwnerCan   []PolicyField `json:"owner_can,omitempty"`
	ManagerCan []PolicyField `json:"manager_can,omitempty"`
	Immutable  []PolicyField `json:"immutable,omitempty"`
}

// Lifecycle defines the key TTL.
type Lifecycle struct {
	TTLSeconds uint64 `json:"ttl_seconds,omitempty"`
}

// KeyPolicy is the full per-key access policy.
type KeyPolicy struct {
	Version    uint32          `json:"version"`
	Principals PrincipalSet    `json:"principals"`
	Operations []OperationRule `json:"operations"`
	Mutability Mutability      `json:"mutability,omitempty"`
	Lifecycle  Lifecycle       `json:"lifecycle,omitempty"`
}

// ApprovalToken carries a JWT issued by IssueApprovalToken.
type ApprovalToken struct {
	JWT string `json:"jwt"`
}

// PendingProfile is a staged-but-not-promoted attestation profile.
type PendingProfile struct {
	ID          uint32               `json:"id"`
	Profile     AttestationProfile   `json:"profile"`
	Source      PendingProfileSource `json:"source"`
	StagedAt    uint64               `json:"staged_at"`
	StagedBySub string               `json:"staged_by_sub"`
}

// KeyInfo is public metadata for a key.
type KeyInfo struct {
	Handle        string  `json:"handle"`
	KeyType       KeyType `json:"key_type"`
	Exportable    bool    `json:"exportable"`
	CreatedAt     uint64  `json:"created_at"`
	ExpiresAt     uint64  `json:"expires_at"`
	PolicyVersion uint32  `json:"policy_version"`
	PublicKey     []byte  `json:"public_key,omitempty"`
}

// KeyListEntry is one entry from VaultRequest::ListKeys.
type KeyListEntry struct {
	Handle    string  `json:"handle"`
	KeyType   KeyType `json:"key_type"`
	ExpiresAt uint64  `json:"expires_at"`
}

// AuditEntry is one row from the per-key audit log.
type AuditEntry struct {
	Seq      uint64        `json:"seq"`
	Ts       uint64        `json:"ts"`
	Op       string        `json:"op"`
	Caller   string        `json:"caller"`
	Decision AuditDecision `json:"decision"`
	Reason   string        `json:"reason,omitempty"`
}

// ----------------------------------------------------------------------
//  Request / Response envelopes
// ----------------------------------------------------------------------

type vaultRequest struct {
	CreateKey             *createKeyReq             `json:"CreateKey,omitempty"`
	ExportKey             *handleApprovalsReq       `json:"ExportKey,omitempty"`
	DeleteKey             *handleApprovalsReq       `json:"DeleteKey,omitempty"`
	UpdatePolicy          *updatePolicyReq          `json:"UpdatePolicy,omitempty"`
	GetPolicy             *handleReq                `json:"GetPolicy,omitempty"`
	GetKeyInfo            *handleReq                `json:"GetKeyInfo,omitempty"`
	ListKeys              bool                      `json:"-"`
	Wrap                  *wrapReq                  `json:"Wrap,omitempty"`
	Unwrap                *unwrapReq                `json:"Unwrap,omitempty"`
	Sign                  *signOrMacReq             `json:"Sign,omitempty"`
	Mac                   *signOrMacReq             `json:"Mac,omitempty"`
	IssueApprovalToken    *issueApprovalTokenReq    `json:"IssueApprovalToken,omitempty"`
	ReadAuditLog          *readAuditLogReq          `json:"ReadAuditLog,omitempty"`
	StagePendingProfile   *stagePendingProfileReq   `json:"StagePendingProfile,omitempty"`
	ListPendingProfiles   *handleReq                `json:"ListPendingProfiles,omitempty"`
	PromotePendingProfile *promotePendingProfileReq `json:"PromotePendingProfile,omitempty"`
	RevokePendingProfile  *revokePendingProfileReq  `json:"RevokePendingProfile,omitempty"`
}

// MarshalJSON: ListKeys is a unit variant â€” encode as the bare string
// "ListKeys", matching serde's default for unit enum variants.
func (vr vaultRequest) MarshalJSON() ([]byte, error) {
	if vr.ListKeys {
		return []byte(`"ListKeys"`), nil
	}
	type alias vaultRequest
	return json.Marshal(alias(vr))
}

type createKeyReq struct {
	Handle      string    `json:"handle"`
	KeyType     KeyType   `json:"key_type"`
	MaterialB64 string    `json:"material_b64"`
	Exportable  bool      `json:"exportable"`
	Policy      KeyPolicy `json:"policy"`
}

type handleReq struct {
	Handle string `json:"handle"`
}

type handleApprovalsReq struct {
	Handle    string          `json:"handle"`
	Approvals []ApprovalToken `json:"approvals,omitempty"`
}

type updatePolicyReq struct {
	Handle    string          `json:"handle"`
	NewPolicy KeyPolicy       `json:"new_policy"`
	Approvals []ApprovalToken `json:"approvals,omitempty"`
}

type wrapReq struct {
	Handle       string          `json:"handle"`
	PlaintextB64 string          `json:"plaintext_b64"`
	AadB64       string          `json:"aad_b64,omitempty"`
	IvB64        string          `json:"iv_b64,omitempty"`
	Approvals    []ApprovalToken `json:"approvals,omitempty"`
}

type unwrapReq struct {
	Handle        string          `json:"handle"`
	CiphertextB64 string          `json:"ciphertext_b64"`
	IvB64         string          `json:"iv_b64"`
	AadB64        string          `json:"aad_b64,omitempty"`
	Approvals     []ApprovalToken `json:"approvals,omitempty"`
}

type signOrMacReq struct {
	Handle     string          `json:"handle"`
	MessageB64 string          `json:"message_b64"`
	Approvals  []ApprovalToken `json:"approvals,omitempty"`
}

type issueApprovalTokenReq struct {
	Handle     string    `json:"handle"`
	Op         Operation `json:"op"`
	TTLSeconds uint64    `json:"ttl_seconds,omitempty"`
}

type readAuditLogReq struct {
	Handle   string `json:"handle"`
	SinceSeq uint64 `json:"since_seq,omitempty"`
	Limit    uint32 `json:"limit,omitempty"`
}

type stagePendingProfileReq struct {
	Handle  string               `json:"handle"`
	Profile AttestationProfile   `json:"profile"`
	Source  PendingProfileSource `json:"source"`
}

type promotePendingProfileReq struct {
	Handle    string          `json:"handle"`
	PendingID uint32          `json:"pending_id"`
	Approvals []ApprovalToken `json:"approvals,omitempty"`
}

type revokePendingProfileReq struct {
	Handle    string `json:"handle"`
	PendingID uint32 `json:"pending_id"`
}

// vaultResponse is the externally-tagged response envelope.
//
// Serde encodes unit variants as bare strings (e.g. "KeyDeleted"); we
// pre-process those in unmarshalResponse to turn them into objects.
type vaultResponse struct {
	KeyCreated *struct {
		Handle    string `json:"handle"`
		ExpiresAt uint64 `json:"expires_at"`
	} `json:"KeyCreated,omitempty"`
	KeyMaterial *struct {
		Material  []byte `json:"material"`
		ExpiresAt uint64 `json:"expires_at"`
	} `json:"KeyMaterial,omitempty"`
	KeyDeleted    *struct{} `json:"KeyDeleted,omitempty"`
	PolicyUpdated *struct {
		PolicyVersion uint32 `json:"policy_version"`
	} `json:"PolicyUpdated,omitempty"`
	Policy *struct {
		Policy        KeyPolicy `json:"policy"`
		PolicyVersion uint32    `json:"policy_version"`
	} `json:"Policy,omitempty"`
	KeyInfo *KeyInfo `json:"KeyInfo,omitempty"`
	KeyList *struct {
		Keys []KeyListEntry `json:"keys"`
	} `json:"KeyList,omitempty"`
	Wrapped *struct {
		Ciphertext []byte `json:"ciphertext"`
		IV         []byte `json:"iv"`
	} `json:"Wrapped,omitempty"`
	Unwrapped *struct {
		Plaintext []byte `json:"plaintext"`
	} `json:"Unwrapped,omitempty"`
	Signature *struct {
		Signature []byte `json:"signature"`
		Alg       string `json:"alg"`
	} `json:"Signature,omitempty"`
	MacTag *struct {
		Mac []byte `json:"mac"`
		Alg string `json:"alg"`
	} `json:"MacTag,omitempty"`
	ApprovalTokenIssued *ApprovalToken `json:"ApprovalTokenIssued,omitempty"`
	AuditLog            *struct {
		Entries []AuditEntry `json:"entries"`
		NextSeq uint64       `json:"next_seq"`
	} `json:"AuditLog,omitempty"`
	PendingProfileStaged *struct {
		PendingID uint32 `json:"pending_id"`
	} `json:"PendingProfileStaged,omitempty"`
	PendingProfileList *struct {
		Pending []PendingProfile `json:"pending"`
	} `json:"PendingProfileList,omitempty"`
	PendingProfilePromoted *struct {
		PolicyVersion uint32 `json:"policy_version"`
	} `json:"PendingProfilePromoted,omitempty"`
	PendingProfileRevoked *struct{} `json:"PendingProfileRevoked,omitempty"`
	Error                 *string   `json:"Error,omitempty"`
}

// errorOr returns ErrVaultError if the response was Error, else nil.
func (vr *vaultResponse) errorOr() error {
	if vr.Error != nil {
		return &ErrVaultError{Message: *vr.Error}
	}
	return nil
}

// unmarshalResponse handles serde's "bare-string for unit variants" case
// by inflating it into an empty object before decoding.
func unmarshalResponse(body []byte) (*vaultResponse, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`) {
		variant := strings.Trim(trimmed, `"`)
		body = []byte(`{"` + variant + `":{}}`)
	}
	var resp vaultResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ===========================================================================
//  AuthTokenSource
// ===========================================================================

// AuthTokenSource provides a fresh OIDC bearer token for vault calls.
//
// Implementations may cache tokens and refresh them as needed. Returning
// "" disables the Authorization header (only useful against an unauth'd
// dev vault).
type AuthTokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken wraps a single static bearer string.
type StaticToken string

func (s StaticToken) Token(_ context.Context) (string, error) { return string(s), nil }

// ===========================================================================
//  Per-vault Client
// ===========================================================================

// DialOptions configures a single-vault Client.
type DialOptions struct {
	// AuthToken supplies the OIDC bearer token sent on every request.
	AuthToken AuthTokenSource

	// CACertPath is an optional PEM CA file used to verify the vault's
	// outer TLS certificate (in addition to RA-TLS quote checks).
	CACertPath string

	// VaultPolicy is the RA-TLS verification policy (acceptable
	// MRENCLAVE / MRSIGNER, attestation servers, etc.). When nil the
	// client trusts the connection without quote verification â€” only
	// safe for local development.
	VaultPolicy *ratls.VerificationPolicy

	// ClientCert supplies a static RA-TLS client certificate for mutual
	// attestation (e.g. enclave-to-vault calls). Unused for plain
	// human-driven calls authenticated by AuthToken.
	ClientCert *tls.Certificate

	// GetClientCertificate is a callback for dynamic RA-TLS client cert
	// generation that binds the server's challenge nonce. Takes
	// precedence over ClientCert when both are set.
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// Client is an authenticated session against a single vault instance.
type Client struct {
	registration VaultRegistration
	opts         DialOptions
	mu           sync.Mutex
	conn         *ratls.Client
}

// Dial opens an RA-TLS connection to a single vault.
func Dial(ctx context.Context, reg VaultRegistration, opts DialOptions) (*Client, error) {
	c := &Client{registration: reg, opts: opts}
	if err := c.reconnect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Registration returns the underlying vault registration.
func (c *Client) Registration() VaultRegistration { return c.registration }

// Close releases the underlying connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *Client) reconnect(ctx context.Context) error {
	_ = ctx // ratls.Connect doesn't take context yet
	rc, err := ratls.Connect(c.registration.Host(), c.registration.Port(), &ratls.Options{
		CACertPath:           c.opts.CACertPath,
		ClientCert:           c.opts.ClientCert,
		GetClientCertificate: c.opts.GetClientCertificate,
	})
	if err != nil {
		return fmt.Errorf("vault %s: ratls dial: %w", c.registration.Endpoint, err)
	}
	if c.opts.VaultPolicy != nil {
		if _, err := rc.VerifyCertificate(c.opts.VaultPolicy); err != nil {
			rc.Close()
			return fmt.Errorf("vault %s: ratls verify: %w", c.registration.Endpoint, err)
		}
	}
	c.conn = rc
	return nil
}

// call sends a VaultRequest and decodes the VaultResponse.
func (c *Client) call(ctx context.Context, req vaultRequest) (*vaultResponse, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var token string
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

	resp, err := unmarshalResponse(body)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w; raw=%s", err, truncate(body, 256))
	}
	return resp, resp.errorOr()
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}

// ----------------------------------------------------------------------
//  Per-vault operations
// ----------------------------------------------------------------------

// CreateKey stores a new key on the vault. Returns the key's expiry (unix
// seconds) on success.
func (c *Client) CreateKey(ctx context.Context, handle string, keyType KeyType,
	material []byte, exportable bool, policy KeyPolicy) (uint64, error) {
	resp, err := c.call(ctx, vaultRequest{CreateKey: &createKeyReq{
		Handle:      handle,
		KeyType:     keyType,
		MaterialB64: base64.RawURLEncoding.EncodeToString(material),
		Exportable:  exportable,
		Policy:      policy,
	}})
	if err != nil {
		return 0, err
	}
	if resp.KeyCreated == nil {
		return 0, ErrUnexpectedResponse
	}
	return resp.KeyCreated.ExpiresAt, nil
}

// ExportKey returns the raw key material (only allowed when exportable
// and the policy grants ExportKey to the caller).
func (c *Client) ExportKey(ctx context.Context, handle string, approvals ...ApprovalToken) ([]byte, error) {
	resp, err := c.call(ctx, vaultRequest{ExportKey: &handleApprovalsReq{
		Handle: handle, Approvals: approvals,
	}})
	if err != nil {
		return nil, err
	}
	if resp.KeyMaterial == nil {
		return nil, ErrUnexpectedResponse
	}
	return resp.KeyMaterial.Material, nil
}

// DeleteKey removes a key and its policy.
func (c *Client) DeleteKey(ctx context.Context, handle string, approvals ...ApprovalToken) error {
	resp, err := c.call(ctx, vaultRequest{DeleteKey: &handleApprovalsReq{
		Handle: handle, Approvals: approvals,
	}})
	if err != nil {
		return err
	}
	if resp.KeyDeleted == nil {
		return ErrUnexpectedResponse
	}
	return nil
}

// UpdatePolicy replaces the policy on an existing key.
func (c *Client) UpdatePolicy(ctx context.Context, handle string, newPolicy KeyPolicy,
	approvals ...ApprovalToken) (uint32, error) {
	resp, err := c.call(ctx, vaultRequest{UpdatePolicy: &updatePolicyReq{
		Handle: handle, NewPolicy: newPolicy, Approvals: approvals,
	}})
	if err != nil {
		return 0, err
	}
	if resp.PolicyUpdated == nil {
		return 0, ErrUnexpectedResponse
	}
	return resp.PolicyUpdated.PolicyVersion, nil
}

// GetPolicy reads the current policy + version for a key.
func (c *Client) GetPolicy(ctx context.Context, handle string) (KeyPolicy, uint32, error) {
	resp, err := c.call(ctx, vaultRequest{GetPolicy: &handleReq{Handle: handle}})
	if err != nil {
		return KeyPolicy{}, 0, err
	}
	if resp.Policy == nil {
		return KeyPolicy{}, 0, ErrUnexpectedResponse
	}
	return resp.Policy.Policy, resp.Policy.PolicyVersion, nil
}

// GetKeyInfo reads public metadata for a key.
func (c *Client) GetKeyInfo(ctx context.Context, handle string) (KeyInfo, error) {
	resp, err := c.call(ctx, vaultRequest{GetKeyInfo: &handleReq{Handle: handle}})
	if err != nil {
		return KeyInfo{}, err
	}
	if resp.KeyInfo == nil {
		return KeyInfo{}, ErrUnexpectedResponse
	}
	return *resp.KeyInfo, nil
}

// ListKeys returns the handles owned by the caller.
func (c *Client) ListKeys(ctx context.Context) ([]KeyListEntry, error) {
	resp, err := c.call(ctx, vaultRequest{ListKeys: true})
	if err != nil {
		return nil, err
	}
	if resp.KeyList == nil {
		return nil, ErrUnexpectedResponse
	}
	return resp.KeyList.Keys, nil
}

// Wrap encrypts plaintext under an Aes256GcmKey. Returns ciphertext, iv.
func (c *Client) Wrap(ctx context.Context, handle string, plaintext, aad, iv []byte,
	approvals ...ApprovalToken) ([]byte, []byte, error) {
	r := &wrapReq{
		Handle:       handle,
		PlaintextB64: base64.RawURLEncoding.EncodeToString(plaintext),
		Approvals:    approvals,
	}
	if len(aad) > 0 {
		r.AadB64 = base64.RawURLEncoding.EncodeToString(aad)
	}
	if len(iv) > 0 {
		r.IvB64 = base64.RawURLEncoding.EncodeToString(iv)
	}
	resp, err := c.call(ctx, vaultRequest{Wrap: r})
	if err != nil {
		return nil, nil, err
	}
	if resp.Wrapped == nil {
		return nil, nil, ErrUnexpectedResponse
	}
	return resp.Wrapped.Ciphertext, resp.Wrapped.IV, nil
}

// Unwrap decrypts ciphertext under an Aes256GcmKey.
func (c *Client) Unwrap(ctx context.Context, handle string, ciphertext, iv, aad []byte,
	approvals ...ApprovalToken) ([]byte, error) {
	r := &unwrapReq{
		Handle:        handle,
		CiphertextB64: base64.RawURLEncoding.EncodeToString(ciphertext),
		IvB64:         base64.RawURLEncoding.EncodeToString(iv),
		Approvals:     approvals,
	}
	if len(aad) > 0 {
		r.AadB64 = base64.RawURLEncoding.EncodeToString(aad)
	}
	resp, err := c.call(ctx, vaultRequest{Unwrap: r})
	if err != nil {
		return nil, err
	}
	if resp.Unwrapped == nil {
		return nil, ErrUnexpectedResponse
	}
	return resp.Unwrapped.Plaintext, nil
}

// Sign produces an IEEE P1363 ECDSA-P256-SHA256 signature.
func (c *Client) Sign(ctx context.Context, handle string, message []byte,
	approvals ...ApprovalToken) ([]byte, string, error) {
	resp, err := c.call(ctx, vaultRequest{Sign: &signOrMacReq{
		Handle:     handle,
		MessageB64: base64.RawURLEncoding.EncodeToString(message),
		Approvals:  approvals,
	}})
	if err != nil {
		return nil, "", err
	}
	if resp.Signature == nil {
		return nil, "", ErrUnexpectedResponse
	}
	return resp.Signature.Signature, resp.Signature.Alg, nil
}

// Mac produces an HMAC-SHA-256 tag.
func (c *Client) Mac(ctx context.Context, handle string, message []byte,
	approvals ...ApprovalToken) ([]byte, string, error) {
	resp, err := c.call(ctx, vaultRequest{Mac: &signOrMacReq{
		Handle:     handle,
		MessageB64: base64.RawURLEncoding.EncodeToString(message),
		Approvals:  approvals,
	}})
	if err != nil {
		return nil, "", err
	}
	if resp.MacTag == nil {
		return nil, "", ErrUnexpectedResponse
	}
	return resp.MacTag.Mac, resp.MacTag.Alg, nil
}

// IssueApprovalToken asks the vault to mint an approval token for a
// specific operation. Caller must be one of policy.principals.managers.
// ttlSeconds = 0 â†’ vault default.
func (c *Client) IssueApprovalToken(ctx context.Context, handle string, op Operation,
	ttlSeconds uint64) (ApprovalToken, error) {
	resp, err := c.call(ctx, vaultRequest{IssueApprovalToken: &issueApprovalTokenReq{
		Handle: handle, Op: op, TTLSeconds: ttlSeconds,
	}})
	if err != nil {
		return ApprovalToken{}, err
	}
	if resp.ApprovalTokenIssued == nil {
		return ApprovalToken{}, ErrUnexpectedResponse
	}
	return *resp.ApprovalTokenIssued, nil
}

// ReadAuditLog fetches audit entries for a key with seq > sinceSeq.
func (c *Client) ReadAuditLog(ctx context.Context, handle string, sinceSeq uint64,
	limit uint32) ([]AuditEntry, uint64, error) {
	resp, err := c.call(ctx, vaultRequest{ReadAuditLog: &readAuditLogReq{
		Handle: handle, SinceSeq: sinceSeq, Limit: limit,
	}})
	if err != nil {
		return nil, 0, err
	}
	if resp.AuditLog == nil {
		return nil, 0, ErrUnexpectedResponse
	}
	return resp.AuditLog.Entries, resp.AuditLog.NextSeq, nil
}

// StagePendingProfile stages an attestation profile on this vault.
func (c *Client) StagePendingProfile(ctx context.Context, handle string,
	profile AttestationProfile, source PendingProfileSource) (uint32, error) {
	resp, err := c.call(ctx, vaultRequest{StagePendingProfile: &stagePendingProfileReq{
		Handle: handle, Profile: profile, Source: source,
	}})
	if err != nil {
		return 0, err
	}
	if resp.PendingProfileStaged == nil {
		return 0, ErrUnexpectedResponse
	}
	return resp.PendingProfileStaged.PendingID, nil
}

// ListPendingProfiles returns currently-staged profiles for a key on
// this vault.
func (c *Client) ListPendingProfiles(ctx context.Context, handle string) ([]PendingProfile, error) {
	resp, err := c.call(ctx, vaultRequest{ListPendingProfiles: &handleReq{Handle: handle}})
	if err != nil {
		return nil, err
	}
	if resp.PendingProfileList == nil {
		return nil, ErrUnexpectedResponse
	}
	return resp.PendingProfileList.Pending, nil
}

// PromotePendingProfile promotes a pending profile into
// policy.principals.tees on this vault.
func (c *Client) PromotePendingProfile(ctx context.Context, handle string,
	pendingID uint32, approvals ...ApprovalToken) (uint32, error) {
	resp, err := c.call(ctx, vaultRequest{PromotePendingProfile: &promotePendingProfileReq{
		Handle: handle, PendingID: pendingID, Approvals: approvals,
	}})
	if err != nil {
		return 0, err
	}
	if resp.PendingProfilePromoted == nil {
		return 0, ErrUnexpectedResponse
	}
	return resp.PendingProfilePromoted.PolicyVersion, nil
}

// RevokePendingProfile drops a pending profile without promoting it.
func (c *Client) RevokePendingProfile(ctx context.Context, handle string,
	pendingID uint32) error {
	resp, err := c.call(ctx, vaultRequest{RevokePendingProfile: &revokePendingProfileReq{
		Handle: handle, PendingID: pendingID,
	}})
	if err != nil {
		return err
	}
	if resp.PendingProfileRevoked == nil {
		return ErrUnexpectedResponse
	}
	return nil
}

// ===========================================================================
//  Constellation â€” fan-out across all live vaults
// ===========================================================================

// EndpointResult is the outcome of one fan-out operation against one vault.
type EndpointResult struct {
	Vault   VaultRegistration
	Success bool
	Err     error
	// PendingID is set by Stage; PolicyVersion is set by Promote;
	// Pending is set by ListPendingProfiles. All are zero/nil when not
	// applicable.
	PendingID     uint32
	PolicyVersion uint32
	Pending       []PendingProfile
}

// Constellation discovers vaults via the registry and fans operations
// out to all of them. Used for cross-vault operations like staging a new
// attestation profile during an enclave upgrade.
type Constellation struct {
	Registry *RegistryClient
	Dial     DialOptions
}

// NewConstellation returns a Constellation backed by the given registry.
func NewConstellation(reg *RegistryClient, dialOpts DialOptions) *Constellation {
	return &Constellation{Registry: reg, Dial: dialOpts}
}

// forEach connects to each live vault and applies fn. Connections are
// closed before the function returns.
func (con *Constellation) forEach(ctx context.Context,
	fn func(*Client) (EndpointResult, error)) ([]EndpointResult, error) {
	vaults, err := con.Registry.ListVaults(ctx)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	if len(vaults) == 0 {
		return nil, errors.New("registry returned no vaults")
	}
	out := make([]EndpointResult, len(vaults))
	for i, v := range vaults {
		c, err := Dial(ctx, v, con.Dial)
		if err != nil {
			out[i] = EndpointResult{Vault: v, Err: err}
			continue
		}
		res, err := fn(c)
		c.Close()
		res.Vault = v
		if err != nil {
			res.Err = err
			res.Success = false
		} else {
			res.Success = true
		}
		out[i] = res
	}
	return out, nil
}

// StagePendingProfile fans StagePendingProfile out to every live vault.
func (con *Constellation) StagePendingProfile(ctx context.Context, handle string,
	profile AttestationProfile, source PendingProfileSource) ([]EndpointResult, error) {
	return con.forEach(ctx, func(c *Client) (EndpointResult, error) {
		id, err := c.StagePendingProfile(ctx, handle, profile, source)
		return EndpointResult{PendingID: id}, err
	})
}

// ListPendingProfiles queries every vault for pending profiles on a key.
// The caller can compare results across vaults to detect divergence.
func (con *Constellation) ListPendingProfiles(ctx context.Context, handle string) ([]EndpointResult, error) {
	return con.forEach(ctx, func(c *Client) (EndpointResult, error) {
		p, err := c.ListPendingProfiles(ctx, handle)
		return EndpointResult{Pending: p}, err
	})
}

// PromotePendingProfile fans PromotePendingProfile out, carrying the
// supplied approval tokens to each vault.
func (con *Constellation) PromotePendingProfile(ctx context.Context, handle string,
	pendingID uint32, approvals ...ApprovalToken) ([]EndpointResult, error) {
	return con.forEach(ctx, func(c *Client) (EndpointResult, error) {
		v, err := c.PromotePendingProfile(ctx, handle, pendingID, approvals...)
		return EndpointResult{PolicyVersion: v}, err
	})
}

// RevokePendingProfile fans RevokePendingProfile out to every vault.
func (con *Constellation) RevokePendingProfile(ctx context.Context, handle string,
	pendingID uint32) ([]EndpointResult, error) {
	return con.forEach(ctx, func(c *Client) (EndpointResult, error) {
		return EndpointResult{}, c.RevokePendingProfile(ctx, handle, pendingID)
	})
}
