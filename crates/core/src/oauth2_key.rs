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
//! # OAuth2 per-domain signing key provider (ADR 0026 §3, Phase 1)
//!
//! Gives each domain its own asymmetric signing keypair, generated
//! synchronously on domain creation and published at
//! `GET /v4/oauth2/{domain_id}/jwks`. Wraps
//! [`openstack_keystone_key_repository::asymmetric::AsymmetricKeyRepository`]
//! the same way [`crate::api_key`] wraps its own storage abstraction:
//! mechanical key generation/storage lives in `key-repository`, the Raft
//! wiring lives in the `oauth2-key-driver-raft` backend crate, and this
//! module is the provider-facing glue (`Oauth2KeyBackend` trait resolved by
//! name via the plugin manager, `Oauth2KeyService` implementing the public
//! `Oauth2KeyApi`).

pub mod backend;
pub mod error;
pub mod hook;
pub mod jwks;
mod provider_api;
pub mod service;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockOauth2KeyProvider;
pub use error::Oauth2KeyProviderError;
pub use hook::Oauth2KeyHook;
pub use provider_api::Oauth2KeyApi;
pub use service::Oauth2KeyService;
