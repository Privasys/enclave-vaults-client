# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

**Do NOT open a public issue.**

Instead, email: **security@privasys.org**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Scope

This policy covers the vault client libraries (Go and Rust), including:
- Shamir Secret Sharing implementation (GF(2^8) arithmetic)
- RA-TLS transport layer usage
- JWT construction and signing
- Secret policy handling

## Cryptographic Components

| Component | Algorithm | Library |
|-----------|-----------|---------|
| Secret Sharing | Shamir SSS over GF(2^8) | Custom (auditable) |
| JWT Signing | ES256 (ECDSA P-256 SHA-256) | Go stdlib / ring |
| Transport | RA-TLS (TLS 1.3 + attestation) | ratls-client |
