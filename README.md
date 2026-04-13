# Enclave Vaults Client

Client libraries for [Enclave Vaults](https://github.com/Privasys/enclave-vaults) — a distributed secret store running inside hardware-attested enclaves.

The vault client distributes secrets across multiple vault instances using **Shamir Secret Sharing** and communicates over **RA-TLS** (Remote Attestation TLS) connections. Compromising fewer than the threshold number of vaults reveals nothing about the stored secrets.

## Architecture

```
 ┌──────────────┐       RA-TLS         ┌─────────────┐
 │              │──── share 1 ────────►│  Vault #1   │
 │  VaultClient │──── share 2 ────────►│  Vault #2   │
 │  (Shamir)    │──── share 3 ────────►│  Vault #3   │
 │              │       ...            │    ...      │
 │              │──── share M ────────►│  Vault #M   │
 └──────────────┘                      └─────────────┘

 Reconstruction: any N-of-M shares → original secret
```

## Available Languages

| Language | Path | Status |
|----------|------|--------|
| **Go** | [`go/vault/`](go/vault/) | Full client + Shamir SSS |
| **Rust** | [`rust/`](rust/) | Full client + Shamir SSS |

## Operations

| Operation | Auth Method | Description |
|-----------|-------------|-------------|
| `StoreSecret` | ES256 JWT (owner key) | Shamir-split and distribute shares |
| `GetSecret` | Mutual RA-TLS (client cert) | Collect threshold shares and reconstruct |
| `DeleteSecret` | ES256 JWT (owner key) | Remove secret from all vaults |
| `UpdatePolicy` | ES256 JWT (owner key) | Update access policy on all vaults |

## Shamir Secret Sharing

Both implementations use identical parameters:

- **Field**: GF(2^8) with irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (0x11b, same as AES)
- **Generator**: g = 3
- **Threshold**: configurable N-of-M (N ≥ 2, M ≤ 255)
- **Per-byte**: independent random polynomial of degree (threshold − 1)

## Quick Start (Go)

```go
import "github.com/Privasys/enclave-vaults-client/go/vault"

config := vault.VaultClientConfig{
    Endpoints: []vault.VaultEndpoint{
        {Host: "vault1.example.com", Port: 8443},
        {Host: "vault2.example.com", Port: 8443},
        {Host: "vault3.example.com", Port: 8443},
    },
    Threshold:  2,
    SigningKey:  ownerKey, // *ecdsa.PrivateKey (P-256)
    CACertPath: "ca.pem",
}

client, err := vault.NewVaultClient(config)
if err != nil {
    log.Fatal(err)
}

// Store — splits into 3 shares (threshold 2)
results, err := client.StoreSecret("my-dek", secretBytes, &vault.SecretPolicy{
    AllowedMREnclave: []string{"abc123..."},
    TTLSeconds:       86400 * 30,
})

// Retrieve — collects 2 shares, reconstructs
reconstructed, err := client.GetSecret("my-dek", nil)
```

## Quick Start (Rust)

```rust
use vault_client::client::{VaultClient, VaultClientConfig, VaultEndpoint, SecretPolicy};

let config = VaultClientConfig {
    endpoints: vec![
        VaultEndpoint { host: "vault1.example.com".into(), port: 8443 },
        VaultEndpoint { host: "vault2.example.com".into(), port: 8443 },
        VaultEndpoint { host: "vault3.example.com".into(), port: 8443 },
    ],
    threshold: 2,
    signing_key_pkcs8: std::fs::read("owner-key.p8")?,
    ca_cert_pem: Some("ca.pem".into()),
    vault_policy: None,
    client_cert_der: None,
    client_key_pkcs8: None,
};

let client = VaultClient::new(config)?;

// Store
let policy = SecretPolicy::new()
    .allow_mrenclave("abc123...")
    .ttl(86400 * 30);
let results = client.store_secret("my-dek", &secret, &policy)?;

// Retrieve
let reconstructed = client.get_secret("my-dek", None)?;
```

## Dependencies

| Language | Dependency | Purpose |
|----------|-----------|---------|
| Go | [`ra-tls-clients/go/ratls`](https://github.com/Privasys/ra-tls-clients) | RA-TLS transport (Connect, SendData, VerifyCertificate) |
| Rust | [`ratls-client`](https://github.com/Privasys/ra-tls-clients) | RA-TLS transport crate |

### Go Local Development

The Go module uses a `replace` directive for local development:

```
replace enclave-os-mini/clients/go => ../../../ra-tls-clients/go
```

Update this path to match your workspace layout, or replace with a tagged version for CI:

```
require github.com/Privasys/ra-tls-clients/go v0.2.0
```

## Running Tests

### Go (Shamir tests)

```bash
cd go
go test ./vault/ -v
```

### Rust (Shamir tests)

```bash
cd rust
cargo test
```

## Related Projects

| Project | Description |
|---------|-------------|
| [enclave-vaults](https://github.com/Privasys/enclave-vaults) | Attested Registry + Vault deployment |
| [enclave-os-mini](https://github.com/Privasys/enclave-os-mini) | SGX enclave runtime (Rust) |
| [enclave-os-virtual](https://github.com/Privasys/enclave-os-virtual) | TDX/SEV-SNP confidential VM runtime (Go) |
| [ra-tls-clients](https://github.com/Privasys/ra-tls-clients) | RA-TLS client libraries |

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
