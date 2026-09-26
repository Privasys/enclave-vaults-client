# Contributing

Thank you for your interest in contributing to Enclave Vaults Client.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch: `git checkout -b feature/my-change`
4. Make your changes
5. Run tests: `cd go && go test ./vault/ -v` or `cd rust && cargo test`
6. Commit with a descriptive message
7. Push and open a Pull Request

## Guidelines

- Follow existing code style and conventions
- Add tests for new functionality
- Keep the Go and Rust implementations feature-equivalent
- Ensure Shamir SSS compatibility between languages (same GF(2^8) parameters)
- Do not introduce new dependencies without discussion

## Code of Conduct

Be respectful and constructive in all interactions.

## Licence and Contributor Licence Agreement

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Before we can merge your first pull request, you need to accept the
[Privasys Contributor Licence Agreement](https://github.com/Privasys/cla). You
keep the copyright in your work; the agreement lets Privasys also license it
under other terms, and Privasys commits to keeping it available under an
open-source licence. A check on your pull request explains how to accept: one
comment, once, for every Privasys repository. If you contribute as part of your
work for an employer, your employer may need to sign the entity agreement
instead.
