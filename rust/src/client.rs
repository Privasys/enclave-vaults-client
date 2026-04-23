// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Enclave Vaults Rust client (constellation-aware, HSM-shaped wire protocol).
//!
//! Compatible with `enclave-os-mini >= 0.19` and the Privasys
//! `enclave-vaults` composition crate.  Replaces the legacy
//! `StoreSecret`/`GetSecret`/`DeleteSecret`/`UpdateSecretPolicy` API.
//!
//! Three layers:
//!
//!  1. [`RegistryClient`] — query the Attested Registry phonebook for live
//!     vault instances.
//!  2. [`Client`] — single-vault RA-TLS session that issues HSM-shaped
//!     requests (`CreateKey`, `Wrap`, `Sign`, etc.).
//!  3. [`Constellation`] — fan-out helpers for cross-vault operations
//!     (chiefly `StagePendingProfile` / `PromotePendingProfile` during an
//!     enclave upgrade).
//!
//! Shamir Secret Sharing helpers ([`crate::shamir`]) are unchanged and
//! used to split a secret into `RawShare` material before [`Client::create_key`].

use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use ratls_client::{RaTlsClient, VerificationPolicy};

// ===========================================================================
//  Errors
// ===========================================================================

/// All errors returned by this crate.
#[derive(Debug)]
pub enum Error {
    /// HTTP / I/O error talking to the registry.
    Registry(String),
    /// Connection or RA-TLS verification error talking to a vault.
    Transport(String),
    /// JSON encoding/decoding error.
    Codec(String),
    /// The vault returned `VaultResponse::Error(msg)`.
    Vault(String),
    /// The vault returned a response variant unrelated to the request.
    UnexpectedResponse,
    /// Configuration error (bad arguments, missing fields, ...).
    Config(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Registry(s) => write!(f, "registry: {s}"),
            Error::Transport(s) => write!(f, "transport: {s}"),
            Error::Codec(s) => write!(f, "codec: {s}"),
            Error::Vault(s) => write!(f, "vault error: {s}"),
            Error::UnexpectedResponse => write!(f, "vault returned unexpected response variant"),
            Error::Config(s) => write!(f, "config: {s}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// ===========================================================================
//  Registry client
// ===========================================================================

/// One vault registration as published by the Attested Registry.
///
/// Mirrors the JSON shape from `platform/enclave-vaults/registry/main.go`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRegistration {
    pub id: String,
    pub endpoint: String,
    pub mrenclave: String,
    #[serde(default)]
    pub mrsigner: String,
    #[serde(rename = "registeredAt")]
    pub registered_at: String,
    #[serde(rename = "lastHeartbeat")]
    pub last_heartbeat: String,
    pub status: String,
}

impl VaultRegistration {
    /// Host portion of `endpoint` (everything before the last colon).
    pub fn host(&self) -> &str {
        match self.endpoint.rfind(':') {
            Some(i) => &self.endpoint[..i],
            None => &self.endpoint,
        }
    }

    /// Port portion of `endpoint`. Defaults to 8443 if missing or invalid.
    pub fn port(&self) -> u16 {
        self.endpoint
            .rfind(':')
            .and_then(|i| self.endpoint[i + 1..].parse().ok())
            .unwrap_or(8443)
    }
}

/// Thin client for the Attested Registry phonebook.
pub struct RegistryClient {
    base_url: String,
    agent: ureq::Agent,
}

impl RegistryClient {
    /// Construct a `RegistryClient` with a 10 s HTTP timeout.
    pub fn new(base_url: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            agent,
        }
    }

    /// Fetch the current set of live vault registrations.
    pub fn list_vaults(&self) -> Result<Vec<VaultRegistration>> {
        #[derive(Deserialize)]
        struct Payload {
            vaults: Vec<VaultRegistration>,
            #[allow(dead_code)]
            #[serde(default)]
            count: u32,
        }

        let url = format!("{}/api/vaults", self.base_url);
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| Error::Registry(e.to_string()))?;
        let body: Payload = resp
            .into_json()
            .map_err(|e| Error::Registry(format!("decode: {e}")))?;
        Ok(body.vaults)
    }
}

// ===========================================================================
//  Wire types — VaultRequest / VaultResponse
//
//  Mirror enclave-os-mini/crates/enclave-os-vault/src/types.rs.
// ===========================================================================

/// Cryptographic type of a stored key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    RawShare,
    Aes256GcmKey,
    P256SigningKey,
    HmacSha256Key,
}

/// Per-key operation grantable by an [`OperationRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    ExportKey,
    DeleteKey,
    UpdatePolicy,
    Wrap,
    Unwrap,
    Sign,
    Mac,
    PromoteProfile,
}

/// Top-level policy field whose mutability can be granted / forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyField {
    Owner,
    Managers,
    Auditors,
    Tees,
    Operations,
    Lifecycle,
    Mutability,
    PendingProfiles,
}

/// Origin of a pending attestation profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingProfileSource {
    PlatformBuild,
    ManualImport,
}

/// Outcome recorded in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditDecision {
    Allowed,
    Denied,
}

// ----------------------------------------------------------------------
//  Principals & attestation
// ----------------------------------------------------------------------

/// One acceptable enclave / VM measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Measurement {
    Mrenclave(String),
    Mrtd(String),
}

/// Pinned attestation verifier endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationServer {
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pinned_spki_sha256_hex: String,
}

/// Required X.509 OID extension on a peer cert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidRequirement {
    pub oid: String,
    pub value: String,
}

/// Attestation profile constraining what a remote TEE quote must satisfy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProfile {
    pub name: String,
    pub measurements: Vec<Measurement>,
    pub attestation_servers: Vec<AttestationServer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_oids: Vec<OidRequirement>,
}

/// OIDC bearer-token authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcPrincipal {
    pub issuer: String,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_roles: Vec<String>,
}

/// FIDO2 authentication (reserved — not yet honoured).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Principal {
    pub rp_id: String,
    pub credential_id_b64: String,
}

/// An identity that can act on a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Principal {
    Oidc(OidcPrincipal),
    Fido2(Fido2Principal),
    Tee(AttestationProfile),
}

/// Named identities of a key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrincipalSet {
    pub owner: Option<Principal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managers: Vec<Principal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auditors: Vec<Principal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tees: Vec<Principal>,
}

/// Reference into a [`PrincipalSet`].
///
/// Wire shape (serde externally-tagged enum):
///
/// - `"Owner"` / `"AnyTee"` (unit variants encoded as bare strings).
/// - `{"Manager": <u32>}` / `{"Auditor": <u32>}` / `{"Tee": <u32>}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalRef {
    Owner,
    AnyTee,
    Manager(u32),
    Auditor(u32),
    Tee(u32),
}

/// Extra access-time predicate attached to an [`OperationRule`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    AttestationMatches(AttestationProfile),
    ManagerApproval {
        manager: u32,
        fresh_for_seconds: u64,
    },
    TimeWindow {
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        not_before: u64,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        not_after: u64,
    },
}

fn is_zero_u64(x: &u64) -> bool {
    *x == 0
}

/// Grants a set of operations to a set of principals, optionally gated by
/// extra conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRule {
    pub ops: Vec<Operation>,
    pub principals: Vec<PrincipalRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Condition>,
}

/// Controls who can change which fields on `UpdatePolicy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Mutability {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_can: Vec<PolicyField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manager_can: Vec<PolicyField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub immutable: Vec<PolicyField>,
}

/// Defines the key TTL.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Lifecycle {
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub ttl_seconds: u64,
}

/// The full per-key access policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    pub version: u32,
    pub principals: PrincipalSet,
    pub operations: Vec<OperationRule>,
    #[serde(default)]
    pub mutability: Mutability,
    #[serde(default)]
    pub lifecycle: Lifecycle,
}

/// JWT minted by `IssueApprovalToken`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub jwt: String,
}

/// Staged-but-not-promoted attestation profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingProfile {
    pub id: u32,
    pub profile: AttestationProfile,
    pub source: PendingProfileSource,
    pub staged_at: u64,
    pub staged_by_sub: String,
}

/// Public metadata for a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub handle: String,
    pub key_type: KeyType,
    pub exportable: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy_version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_key: Vec<u8>,
}

/// One entry from `VaultRequest::ListKeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyListEntry {
    pub handle: String,
    pub key_type: KeyType,
    pub expires_at: u64,
}

/// One row from the per-key audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: u64,
    pub op: String,
    pub caller: String,
    pub decision: AuditDecision,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

// ----------------------------------------------------------------------
//  Request / Response envelopes
// ----------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(tag = "_dummy")]
enum _SerdeAnchor {} // unused — kept to remind that VaultRequest is hand-shaped

#[derive(Debug, Serialize)]
enum VaultRequest<'a> {
    CreateKey {
        handle: &'a str,
        key_type: KeyType,
        material_b64: String,
        exportable: bool,
        policy: &'a KeyPolicy,
    },
    ExportKey {
        handle: &'a str,
        approvals: &'a [ApprovalToken],
    },
    DeleteKey {
        handle: &'a str,
        approvals: &'a [ApprovalToken],
    },
    UpdatePolicy {
        handle: &'a str,
        new_policy: &'a KeyPolicy,
        approvals: &'a [ApprovalToken],
    },
    GetPolicy {
        handle: &'a str,
    },
    GetKeyInfo {
        handle: &'a str,
    },
    ListKeys,
    Wrap {
        handle: &'a str,
        plaintext_b64: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        aad_b64: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        iv_b64: Option<String>,
        approvals: &'a [ApprovalToken],
    },
    Unwrap {
        handle: &'a str,
        ciphertext_b64: String,
        iv_b64: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        aad_b64: Option<String>,
        approvals: &'a [ApprovalToken],
    },
    Sign {
        handle: &'a str,
        message_b64: String,
        approvals: &'a [ApprovalToken],
    },
    Mac {
        handle: &'a str,
        message_b64: String,
        approvals: &'a [ApprovalToken],
    },
    IssueApprovalToken {
        handle: &'a str,
        op: Operation,
        ttl_seconds: u64,
    },
    ReadAuditLog {
        handle: &'a str,
        since_seq: u64,
        limit: u32,
    },
    StagePendingProfile {
        handle: &'a str,
        profile: &'a AttestationProfile,
        source: PendingProfileSource,
    },
    ListPendingProfiles {
        handle: &'a str,
    },
    PromotePendingProfile {
        handle: &'a str,
        pending_id: u32,
        approvals: &'a [ApprovalToken],
    },
    RevokePendingProfile {
        handle: &'a str,
        pending_id: u32,
    },
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // serde reads every field; not all are exposed by the SDK API
enum VaultResponse {
    KeyCreated {
        handle: String,
        expires_at: u64,
    },
    KeyMaterial {
        material: Vec<u8>,
        expires_at: u64,
    },
    KeyDeleted,
    PolicyUpdated {
        policy_version: u32,
    },
    Policy {
        policy: KeyPolicy,
        policy_version: u32,
    },
    KeyInfo(KeyInfo),
    KeyList {
        keys: Vec<KeyListEntry>,
    },
    Wrapped {
        ciphertext: Vec<u8>,
        iv: Vec<u8>,
    },
    Unwrapped {
        plaintext: Vec<u8>,
    },
    Signature {
        signature: Vec<u8>,
        alg: String,
    },
    MacTag {
        mac: Vec<u8>,
        alg: String,
    },
    ApprovalTokenIssued(ApprovalToken),
    AuditLog {
        entries: Vec<AuditEntry>,
        next_seq: u64,
    },
    PendingProfileStaged {
        pending_id: u32,
    },
    PendingProfileList {
        pending: Vec<PendingProfile>,
    },
    PendingProfilePromoted {
        policy_version: u32,
    },
    PendingProfileRevoked,
    Error(String),
}

// ===========================================================================
//  AuthTokenSource
// ===========================================================================

/// Provides a fresh OIDC bearer token for vault calls.
///
/// Returning `None` (or `""`) suppresses the `Authorization` header — only
/// useful against an unauth'd dev vault.
pub trait AuthTokenSource: Send + Sync {
    fn token(&self) -> Result<Option<String>>;
}

/// Static bearer string (useful for tests).
pub struct StaticToken(pub String);

impl AuthTokenSource for StaticToken {
    fn token(&self) -> Result<Option<String>> {
        Ok(if self.0.is_empty() {
            None
        } else {
            Some(self.0.clone())
        })
    }
}

// ===========================================================================
//  Per-vault Client
// ===========================================================================

/// Configuration for a single-vault [`Client`].
pub struct DialOptions {
    /// Supplies the OIDC bearer token sent on every request.
    pub auth: Option<Box<dyn AuthTokenSource>>,

    /// Optional PEM CA file used to verify the vault's outer TLS certificate
    /// (in addition to RA-TLS quote checks).
    pub ca_cert_pem: Option<String>,

    /// RA-TLS verification policy. When `None`, quote verification is
    /// skipped — only safe for local development.
    pub vault_policy: Option<VerificationPolicy>,

    /// Static RA-TLS client certificate chain (DER, leaf first) for mutual
    /// attestation (e.g. enclave-to-vault calls).
    pub client_cert_der: Option<Vec<Vec<u8>>>,

    /// PKCS#8 DER-encoded private key matching `client_cert_der`.
    pub client_key_pkcs8: Option<Vec<u8>>,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            auth: None,
            ca_cert_pem: None,
            vault_policy: None,
            client_cert_der: None,
            client_key_pkcs8: None,
        }
    }
}

/// Authenticated session against a single vault instance.
pub struct Client {
    registration: VaultRegistration,
    opts: DialOptions,
    conn: Mutex<Option<RaTlsClient>>,
}

impl Client {
    /// Open an RA-TLS connection to a single vault.
    pub fn dial(reg: VaultRegistration, opts: DialOptions) -> Result<Self> {
        let mut c = Self {
            registration: reg,
            opts,
            conn: Mutex::new(None),
        };
        c.connect_locked()?;
        Ok(c)
    }

    /// Underlying registration record.
    pub fn registration(&self) -> &VaultRegistration {
        &self.registration
    }

    fn connect_locked(&mut self) -> Result<()> {
        let conn = self.open_connection()?;
        *self.conn.lock().unwrap() = Some(conn);
        Ok(())
    }

    fn open_connection(&self) -> Result<RaTlsClient> {
        let ca = self.opts.ca_cert_pem.as_deref();
        let host = self.registration.host();
        let port = self.registration.port();

        let conn = match (&self.opts.client_cert_der, &self.opts.client_key_pkcs8) {
            (Some(chain), Some(key)) => RaTlsClient::connect_mutual(
                host,
                port,
                ca,
                chain.clone(),
                key.clone(),
            )
            .map_err(|e| Error::Transport(format!("mutual ratls dial {host}:{port}: {e}")))?,
            _ => RaTlsClient::connect(host, port, ca)
                .map_err(|e| Error::Transport(format!("ratls dial {host}:{port}: {e}")))?,
        };

        if let Some(policy) = &self.opts.vault_policy {
            conn.verify_certificate(policy)
                .map_err(|e| Error::Transport(format!("ratls verify {host}:{port}: {e}")))?;
        }

        Ok(conn)
    }

    /// Send a `VaultRequest` and decode the `VaultResponse`. Retries once
    /// on transport failure with a fresh connection.
    fn call(&self, req: &VaultRequest<'_>) -> Result<VaultResponse> {
        let payload =
            serde_json::to_vec(req).map_err(|e| Error::Codec(format!("serialise: {e}")))?;

        let token = match &self.opts.auth {
            Some(src) => src.token()?,
            None => None,
        };
        let token_ref = token.as_deref();

        let body = {
            let mut guard = self.conn.lock().unwrap();
            if guard.is_none() {
                *guard = Some(self.open_connection()?);
            }

            let first_err = match guard
                .as_mut()
                .unwrap()
                .send_data(&payload, token_ref)
            {
                Ok(b) => return decode_response(&b),
                Err(e) => e,
            };

            // Retry once on transport error with a fresh connection.
            *guard = None;
            *guard = Some(self.open_connection().map_err(|e| {
                Error::Transport(format!(
                    "send failed ({first_err}); reconnect failed: {e}"
                ))
            })?);
            guard
                .as_mut()
                .unwrap()
                .send_data(&payload, token_ref)
                .map_err(|e| Error::Transport(format!("send: {e}")))?
        };

        decode_response(&body)
    }

    // -------------------------------------------------------------------
    //  Operations
    // -------------------------------------------------------------------

    /// Store a new key. Returns the expiry (unix seconds) on success.
    pub fn create_key(
        &self,
        handle: &str,
        key_type: KeyType,
        material: &[u8],
        exportable: bool,
        policy: &KeyPolicy,
    ) -> Result<u64> {
        let resp = self.call(&VaultRequest::CreateKey {
            handle,
            key_type,
            material_b64: URL_SAFE_NO_PAD.encode(material),
            exportable,
            policy,
        })?;
        match resp {
            VaultResponse::KeyCreated { expires_at, .. } => Ok(expires_at),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Export raw key material (only when `exportable` and the policy
    /// grants `ExportKey` to the caller).
    pub fn export_key(&self, handle: &str, approvals: &[ApprovalToken]) -> Result<Vec<u8>> {
        match self.call(&VaultRequest::ExportKey { handle, approvals })? {
            VaultResponse::KeyMaterial { material, .. } => Ok(material),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete a key and its policy.
    pub fn delete_key(&self, handle: &str, approvals: &[ApprovalToken]) -> Result<()> {
        match self.call(&VaultRequest::DeleteKey { handle, approvals })? {
            VaultResponse::KeyDeleted => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Replace the policy on an existing key. Returns the new
    /// `policy_version`.
    pub fn update_policy(
        &self,
        handle: &str,
        new_policy: &KeyPolicy,
        approvals: &[ApprovalToken],
    ) -> Result<u32> {
        match self.call(&VaultRequest::UpdatePolicy {
            handle,
            new_policy,
            approvals,
        })? {
            VaultResponse::PolicyUpdated { policy_version } => Ok(policy_version),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Read the current policy + version for a key.
    pub fn get_policy(&self, handle: &str) -> Result<(KeyPolicy, u32)> {
        match self.call(&VaultRequest::GetPolicy { handle })? {
            VaultResponse::Policy {
                policy,
                policy_version,
            } => Ok((policy, policy_version)),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Read public metadata for a key.
    pub fn get_key_info(&self, handle: &str) -> Result<KeyInfo> {
        match self.call(&VaultRequest::GetKeyInfo { handle })? {
            VaultResponse::KeyInfo(info) => Ok(info),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// List all keys owned by the caller.
    pub fn list_keys(&self) -> Result<Vec<KeyListEntry>> {
        match self.call(&VaultRequest::ListKeys)? {
            VaultResponse::KeyList { keys } => Ok(keys),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Encrypt under an `Aes256GcmKey`. Returns `(ciphertext, iv)`.
    pub fn wrap(
        &self,
        handle: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        iv: Option<&[u8]>,
        approvals: &[ApprovalToken],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let req = VaultRequest::Wrap {
            handle,
            plaintext_b64: URL_SAFE_NO_PAD.encode(plaintext),
            aad_b64: aad.map(|a| URL_SAFE_NO_PAD.encode(a)),
            iv_b64: iv.map(|i| URL_SAFE_NO_PAD.encode(i)),
            approvals,
        };
        match self.call(&req)? {
            VaultResponse::Wrapped { ciphertext, iv } => Ok((ciphertext, iv)),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Decrypt under an `Aes256GcmKey`.
    pub fn unwrap(
        &self,
        handle: &str,
        ciphertext: &[u8],
        iv: &[u8],
        aad: Option<&[u8]>,
        approvals: &[ApprovalToken],
    ) -> Result<Vec<u8>> {
        let req = VaultRequest::Unwrap {
            handle,
            ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
            iv_b64: URL_SAFE_NO_PAD.encode(iv),
            aad_b64: aad.map(|a| URL_SAFE_NO_PAD.encode(a)),
            approvals,
        };
        match self.call(&req)? {
            VaultResponse::Unwrapped { plaintext } => Ok(plaintext),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Produce an IEEE P1363 ECDSA-P256-SHA256 signature.
    pub fn sign(
        &self,
        handle: &str,
        message: &[u8],
        approvals: &[ApprovalToken],
    ) -> Result<(Vec<u8>, String)> {
        match self.call(&VaultRequest::Sign {
            handle,
            message_b64: URL_SAFE_NO_PAD.encode(message),
            approvals,
        })? {
            VaultResponse::Signature { signature, alg } => Ok((signature, alg)),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Produce an HMAC-SHA-256 tag.
    pub fn mac(
        &self,
        handle: &str,
        message: &[u8],
        approvals: &[ApprovalToken],
    ) -> Result<(Vec<u8>, String)> {
        match self.call(&VaultRequest::Mac {
            handle,
            message_b64: URL_SAFE_NO_PAD.encode(message),
            approvals,
        })? {
            VaultResponse::MacTag { mac, alg } => Ok((mac, alg)),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Mint an approval token for an operation. Caller must be a manager
    /// in the policy. `ttl_seconds = 0` → vault default.
    pub fn issue_approval_token(
        &self,
        handle: &str,
        op: Operation,
        ttl_seconds: u64,
    ) -> Result<ApprovalToken> {
        match self.call(&VaultRequest::IssueApprovalToken {
            handle,
            op,
            ttl_seconds,
        })? {
            VaultResponse::ApprovalTokenIssued(t) => Ok(t),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Fetch audit entries with `seq > since_seq` (up to `limit`).
    pub fn read_audit_log(
        &self,
        handle: &str,
        since_seq: u64,
        limit: u32,
    ) -> Result<(Vec<AuditEntry>, u64)> {
        match self.call(&VaultRequest::ReadAuditLog {
            handle,
            since_seq,
            limit,
        })? {
            VaultResponse::AuditLog { entries, next_seq } => Ok((entries, next_seq)),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Stage an attestation profile on this vault. Returns the
    /// `pending_id` (vault-local).
    pub fn stage_pending_profile(
        &self,
        handle: &str,
        profile: &AttestationProfile,
        source: PendingProfileSource,
    ) -> Result<u32> {
        match self.call(&VaultRequest::StagePendingProfile {
            handle,
            profile,
            source,
        })? {
            VaultResponse::PendingProfileStaged { pending_id } => Ok(pending_id),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// List currently-staged profiles for a key.
    pub fn list_pending_profiles(&self, handle: &str) -> Result<Vec<PendingProfile>> {
        match self.call(&VaultRequest::ListPendingProfiles { handle })? {
            VaultResponse::PendingProfileList { pending } => Ok(pending),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Promote a pending profile into `principals.tees`. Returns the new
    /// `policy_version`.
    pub fn promote_pending_profile(
        &self,
        handle: &str,
        pending_id: u32,
        approvals: &[ApprovalToken],
    ) -> Result<u32> {
        match self.call(&VaultRequest::PromotePendingProfile {
            handle,
            pending_id,
            approvals,
        })? {
            VaultResponse::PendingProfilePromoted { policy_version } => Ok(policy_version),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Drop a pending profile without promoting it.
    pub fn revoke_pending_profile(&self, handle: &str, pending_id: u32) -> Result<()> {
        match self.call(&VaultRequest::RevokePendingProfile { handle, pending_id })? {
            VaultResponse::PendingProfileRevoked => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }
}

// ===========================================================================
//  Decode helper (handles serde's bare-string unit-variant encoding)
// ===========================================================================

fn decode_response(body: &[u8]) -> Result<VaultResponse> {
    // Serde encodes unit enum variants as bare JSON strings (e.g.
    // `"KeyDeleted"`). Inflate those to `{"KeyDeleted": null}` for
    // serde_json's tag dispatch.
    let trimmed_len = body.iter().rev().take_while(|b| b.is_ascii_whitespace()).count();
    let body = &body[..body.len() - trimmed_len];
    let body = body.iter().position(|b| !b.is_ascii_whitespace()).map_or(body, |i| &body[i..]);

    let resp: VaultResponse = if body.first() == Some(&b'"') && body.last() == Some(&b'"') {
        let variant = std::str::from_utf8(&body[1..body.len() - 1])
            .map_err(|e| Error::Codec(format!("non-utf8 variant: {e}")))?;
        let inflated = format!(r#"{{"{variant}":null}}"#);
        serde_json::from_str(&inflated)
            .map_err(|e| Error::Codec(format!("inflate {variant}: {e}")))?
    } else {
        serde_json::from_slice(body)
            .map_err(|e| Error::Codec(format!("parse response: {e}")))?
    };

    if let VaultResponse::Error(msg) = resp {
        return Err(Error::Vault(msg));
    }
    Ok(resp)
}

// ===========================================================================
//  Constellation — fan-out across all live vaults
// ===========================================================================

/// Outcome of one fan-out operation against one vault.
pub struct EndpointResult {
    pub vault: VaultRegistration,
    pub result: Result<EndpointPayload>,
}

/// Per-operation success payload returned by [`Constellation`] fan-outs.
pub enum EndpointPayload {
    /// Returned by `stage_pending_profile`.
    PendingId(u32),
    /// Returned by `promote_pending_profile`.
    PolicyVersion(u32),
    /// Returned by `list_pending_profiles`.
    Pending(Vec<PendingProfile>),
    /// Returned by `revoke_pending_profile` (no payload).
    Empty,
}

/// Fan-out helper for cross-vault operations.
///
/// Each call to a `Constellation` method:
///
///  1. Lists vaults from the registry.
///  2. Dials each one in turn (sequentially, dropping the connection
///     before moving on).
///  3. Returns one [`EndpointResult`] per vault.
pub struct Constellation {
    pub registry: RegistryClient,
    /// Builder closure invoked once per vault to produce a fresh
    /// [`DialOptions`]. Required because [`AuthTokenSource`] is not `Clone`.
    pub dial: Box<dyn Fn() -> DialOptions + Send + Sync>,
}

impl Constellation {
    /// Construct a `Constellation`.
    pub fn new(
        registry: RegistryClient,
        dial: impl Fn() -> DialOptions + Send + Sync + 'static,
    ) -> Self {
        Self {
            registry,
            dial: Box::new(dial),
        }
    }

    fn for_each<F>(&self, mut f: F) -> Result<Vec<EndpointResult>>
    where
        F: FnMut(&Client) -> Result<EndpointPayload>,
    {
        let vaults = self.registry.list_vaults()?;
        if vaults.is_empty() {
            return Err(Error::Registry("no vaults registered".into()));
        }
        let mut out = Vec::with_capacity(vaults.len());
        for v in vaults {
            let opts = (self.dial)();
            let res = match Client::dial(v.clone(), opts) {
                Ok(c) => f(&c),
                Err(e) => Err(e),
            };
            out.push(EndpointResult { vault: v, result: res });
        }
        Ok(out)
    }

    /// Stage `profile` on every live vault.
    pub fn stage_pending_profile(
        &self,
        handle: &str,
        profile: &AttestationProfile,
        source: PendingProfileSource,
    ) -> Result<Vec<EndpointResult>> {
        self.for_each(|c| {
            c.stage_pending_profile(handle, profile, source)
                .map(EndpointPayload::PendingId)
        })
    }

    /// Query every live vault for pending profiles on `handle`.
    pub fn list_pending_profiles(&self, handle: &str) -> Result<Vec<EndpointResult>> {
        self.for_each(|c| c.list_pending_profiles(handle).map(EndpointPayload::Pending))
    }

    /// Promote `pending_id` on every live vault, carrying `approvals`.
    pub fn promote_pending_profile(
        &self,
        handle: &str,
        pending_id: u32,
        approvals: &[ApprovalToken],
    ) -> Result<Vec<EndpointResult>> {
        self.for_each(|c| {
            c.promote_pending_profile(handle, pending_id, approvals)
                .map(EndpointPayload::PolicyVersion)
        })
    }

    /// Revoke `pending_id` on every live vault.
    pub fn revoke_pending_profile(
        &self,
        handle: &str,
        pending_id: u32,
    ) -> Result<Vec<EndpointResult>> {
        self.for_each(|c| {
            c.revoke_pending_profile(handle, pending_id)
                .map(|()| EndpointPayload::Empty)
        })
    }
}
