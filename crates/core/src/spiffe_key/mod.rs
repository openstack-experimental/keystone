// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # SPIFFE attestation signing key provider (SPIRE integration plan, Phase 2)
//!
//! Gives each domain its own asymmetric attestation signing keypair,
//! published at `GET /v4/spiffe/{domain_id}/jwks` and used to sign
//! `POST /v4/vendordata` JWTs. Deliberately independent from
//! [`crate::oauth2_key`]'s signing key -- see
//! `doc/src/adr/0032-vendor-data-jwt.md`, "Attestation key isolation".

mod provider_api;
mod service;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockSpiffeKeyProvider;
pub use openstack_keystone_core_types::spiffe_key::SpiffeKeyProviderError;
pub use provider_api::SpiffeKeyApi;
pub use service::SpiffeKeyService;
