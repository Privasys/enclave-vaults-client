# Enclave Vaults — Client SDKs

Go and Rust client libraries for [Enclave Vaults](https://github.com/Privasys/enclave-vaults), Privasys's distributed virtual HSM running inside SGX enclaves.

The SDKs talk to a **constellation of independent vault enclaves** over RA-TLS. Each vault enforces a per-key `KeyPolicy`, performs typed HSM operations in-enclave (no raw key material on the wire), and seals state to its own MRENCLAVE. Information-theoretic confidentiality of secrets that opt into Shamir storage is preserved by k-of-n sharding across vaults; for HSM-shaped keys (sign / wrap / derive), each vault holds a full copy of the key under its own seal and the SDK fans calls out.

The **registry** is a phonebook only: `GET /api/vaults` returns `(endpoint, measurement)` tuples. It never sees keys, shares, policies, pending profiles, approval tokens, or audit data — the SDK does its own RA-TLS handshake and quote verification against each vault directly.

## Layout

| Language | Path                                          | Crate / module                                                   |
| -------- | --------------------------------------------- | ---------------------------------------------------------------- |
| Go       | [`go/vault/`](go/vault/)                      | `github.com/Privasys/enclave-vaults-client/go/vault`             |
| Rust     | [`rust/`](rust/) (crate `enclave-vaults-client`) | `enclave_vaults_client::client`                                |

Both implementations expose the **same three layers**:

| Layer            | Type                                       | Responsibility                                                                                                                |
| ---------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| Discovery        | `RegistryClient`                           | Plain HTTPS to `https://<registry>/api/vaults`. Returns the live `VaultRegistration` list (host, port, MRENCLAVE).            |
| Single vault     | `Client` (`Dial(ctx, registration, opts)`) | RA-TLS handshake + quote verification against one vault. Exposes the 16 HSM operations.                                       |
| Whole constellation | `Constellation` / `NewConstellation(reg, opts)` | Pulls the registry, dials each vault, and fans calls out (Shamir distribution, pending-profile staging/promotion/revoke). |

## The 16 HSM operations

Each `Client` instance is a single RA-TLS session to one vault. All operations are JSON-over-HTTP/1.1 inside the RA-TLS tunnel.

| Operation               | Purpose                                                                              | Authenticator                       |
| ----------------------- | ------------------------------------------------------------------------------------ | ----------------------------------- |
| `CreateKey`             | Create a typed key with an attached `KeyPolicy`                                      | OIDC owner JWT                      |
| `ImportKey`             | Import existing material under a `KeyPolicy`                                         | OIDC owner JWT                      |
| `ExportKey`             | Export raw material (only if `usage.export` and the policy allows)                   | OIDC + optional manager approvals   |
| `DeleteKey`             | Tombstone a key                                                                      | OIDC + optional manager approvals   |
| `RotateKey`             | Bump the version, optionally swap policy                                             | OIDC + per-policy `Mutability`      |
| `ListKeys`              | List handles visible to the caller                                                   | OIDC                                |
| `GetKeyInfo`            | Metadata + public components only (no sealed material)                               | OIDC or attested TEE                |
| `Wrap` / `Unwrap`       | AES-256-GCM with sealed KEK; AAD + IV verbatim                                       | Attested TEE (RA-TLS) or OIDC       |
| `Sign` / `Verify`       | P-256 / Ed25519, hash inside the enclave                                             | Attested TEE or OIDC                |
| `Mac`                   | HMAC-SHA-256                                                                         | Attested TEE or OIDC                |
| `UpdatePolicy`          | Diff-style policy update; respects `Mutability` and may need approval tokens         | OIDC + manager approvals            |
| `GetPolicy`             | Returns the current policy + `policy_version`                                        | OIDC or attested TEE                |
| `IssueApprovalToken`    | Manager mints a short-lived approval blob for a specific `(handle, op)`              | Manager OIDC (or FIDO2 in the wallet) |
| `ReadAuditLog`          | Sealed append-only log; one entry per attempted op                                   | OIDC owner / auditor                |

Pending-profile lifecycle (used during enclave upgrades) lives on the same `Client`:

`StagePendingProfile`, `ListPendingProfiles`, `PromotePendingProfile`, `RevokePendingProfile` — and the matching `Constellation` methods that fan them out across the vaults that hold a share of the key.

## OIDC

By default the SDK accepts JWTs from **Privasys ID** (`https://privasys.id`, audience `privasys-platform`, JWKS at `https://privasys.id/jwks`). Roles are matched as raw strings on `claims.roles`:

- `vault:owner` — create / delete / rotate / export their own keys
- `vault:manager` — co-sign approvals (export, policy changes, profile promotions)
- `vault:auditor` — read `GetPolicy` + `ReadAuditLog`, nothing else

Bring-your-own IdP is supported by the vault binary (`oidc_issuer_url` + matching `Principal::Oidc { issuer }` in policies); from the SDK side, just pass tokens minted by your IdP via the `TokenSource` interface.

## Go quick start

```go
import (
    "context"
    "fmt"

    vault "github.com/Privasys/enclave-vaults-client/go/vault"
)

func main() {
    ctx := context.Background()

    // 1. Discover the constellation.
    reg := vault.NewRegistryClient("https://u.registry.vaults.privasys.org")

    // 2. Dial options shared by every vault in the constellation:
    //    OIDC token source + (optional) custom CA bundle for the attestation server.
    dial := vault.DialOptions{
        Token:               vault.StaticToken(os.Getenv("PRIVASYS_ID_JWT")),
        AttestationServer:   "https://as.privasys.org",
    }

    // 3a. Talk to one vault directly.
    vaults, _ := reg.ListVaults(ctx)
    cli, _ := vault.Dial(ctx, vaults[0], dial)
    defer cli.Close()

    sig, alg, err := cli.Sign(ctx, "vault:tenant42/release-signer/v1",
        []byte("payload to sign"), "sha256")
    fmt.Printf("alg=%s sig_len=%d err=%v\n", alg, len(sig), err)

    // 3b. Or fan out to the whole constellation (Shamir / pending profiles).
    con := vault.NewConstellation(reg, dial)
    results, _ := con.StagePendingProfile(ctx, "vault:tenant42/master-kek/v1",
        vault.AttestationProfile{
            Name:                      "app:v3 / SGX",
            Measurements:              []vault.Measurement{vault.Mrenclave("a1b2…")},
            AttestationServers:        []string{"https://as.privasys.org"},
            QuoteFreshnessMaxSeconds:  60,
        },
        vault.PendingProfileSource{Kind: vault.PendingProfileSourcePlatformBuild},
    )
    for _, r := range results {
        fmt.Printf("%s: ok=%v err=%v pending_id=%d\n",
            r.Vault.Host(), r.Success, r.Err, r.PendingID)
    }
}
```

## Rust quick start

```rust
use enclave_vaults_client::client::{
    AttestationProfile, Constellation, DialOptions, Measurement,
    PendingProfileSource, RegistryClient, StaticToken, dial,
};

fn main() -> anyhow::Result<()> {
    // 1. Discover the constellation.
    let reg = RegistryClient::new("https://u.registry.vaults.privasys.org");

    // 2. Dial options shared by every vault.
    let opts = DialOptions {
        token: Some(Box::new(StaticToken(std::env::var("PRIVASYS_ID_JWT")?))),
        attestation_server: Some("https://as.privasys.org".into()),
        ..Default::default()
    };

    // 3a. One vault.
    let vaults = reg.list_vaults()?;
    let mut cli = dial(&vaults[0], &opts)?;
    let (sig, alg) = cli.sign("vault:tenant42/release-signer/v1",
                              b"payload to sign", "sha256")?;
    println!("alg={alg} sig_len={}", sig.len());

    // 3b. Whole constellation.
    let con = Constellation::new(reg, opts);
    let results = con.stage_pending_profile(
        "vault:tenant42/master-kek/v1",
        AttestationProfile {
            name: "app:v3 / SGX".into(),
            measurements: vec![Measurement::Mrenclave("a1b2…".into())],
            attestation_servers: vec!["https://as.privasys.org".into()],
            quote_freshness_max_seconds: 60,
            ..Default::default()
        },
        PendingProfileSource::PlatformBuild,
    )?;
    for r in &results {
        println!("{}: ok={} err={:?} pending_id={:?}",
                 r.vault.host(), r.success, r.err, r.pending_id);
    }
    Ok(())
}
```

## Shamir helper (legacy `RawShare` keys)

The `RawShare` key type stores Shamir shares of an external secret (the original v0.1 use case — sealing an app's KV master key behind k-of-n SGX enclaves). Both SDKs ship the same finite-field implementation:

- GF(2⁸) with AES's irreducible polynomial `x⁸ + x⁴ + x³ + x + 1` (`0x11b`)
- Generator `g = 3`
- Per-byte independent random polynomial of degree `threshold − 1`
- Threshold ≥ 2, ≤ 255 shares total

Helpers: `vault.SplitShares(secret, threshold, n)` / `vault.CombineShares(shares)` (Go) and `enclave_vaults_client::shamir::{split, combine}` (Rust). Tests: `cd go && go test ./vault/ -v` and `cd rust && cargo test`.

## Trust model in one sentence

> The SDK trusts only attested vault enclaves it has handshaken with itself; it never trusts the registry for anything beyond endpoint discovery, and approval tokens travel SDK → vault end-to-end without ever transiting the registry.

## Related

| Project                                                                          | Description                                                                                |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| [enclave-vaults](https://github.com/Privasys/enclave-vaults)                     | Vault enclave composition + Attested Registry                                              |
| [enclave-os-mini](https://github.com/Privasys/enclave-os-mini)                   | SGX runtime; ships the `enclave-os-vault` module                                           |
| [ra-tls-clients](https://github.com/Privasys/ra-tls-clients)                     | RA-TLS client transport (Go + Rust); used by this SDK                                      |
| [Privasys ID](https://privasys.id)                                               | Default OIDC IdP                                                                           |

## License

[GNU Affero General Public License v3.0](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.
