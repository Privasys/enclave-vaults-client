// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Enclave Vaults Rust client.
//!
//! Two top-level modules:
//!
//! - [`client`] — constellation-aware, HSM-shaped vault client compatible
//!   with `enclave-os-mini >= 0.19`. Provides registry discovery,
//!   single-vault key operations, and cross-vault fan-out.
//! - [`shamir`] — Shamir Secret Sharing over GF(2^8), used to split a
//!   secret into `RawShare` material before [`client::Client::create_key`].
//!
//! See the [`client`] module documentation for end-to-end examples.

pub mod client;
pub mod shamir;
