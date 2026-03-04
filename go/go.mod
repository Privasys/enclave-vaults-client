// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

module github.com/Privasys/enclave-vaults-client/go

go 1.22

require enclave-os-mini/clients/go v0.0.0

// For local development, point to sibling checkout of ra-tls-clients.
// In CI / consumers, replace with a tagged version or git commit hash:
//   require github.com/Privasys/ra-tls-clients/go v0.2.0
replace enclave-os-mini/clients/go => ../../ra-tls-clients/go
