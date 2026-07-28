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
//! # Policy store provider
//!
//! Backs the legacy `/v3/policies` API: CRUD over opaque, arbitrarily
//! serialized policy documents that *remote* services fetch and interpret
//! themselves.
//!
//! ## This is not authorization
//!
//! Keystone's own access control is decided by OPA/Rego — see
//! [`crate::policy`] for the enforcement client and `policy/**/*.rego` for
//! the rules. A stored [`Policy`] is inert data this service never reads or
//! evaluates. The two are unrelated despite the shared word, which is why
//! this domain is `policy_store` and not `policy`.
//!
//! Python keystone's api-ref marks the API deprecated ("Keystone is not a
//! policy management service"); it exists here only for API compatibility
//! with the python implementation (issue #1035).
//!
//! [`Policy`]: openstack_keystone_core_types::policy_store::Policy

pub mod backend;
pub mod error;
mod provider_api;
pub mod service;

pub use error::PolicyStoreProviderError;
pub use provider_api::PolicyStoreApi;
pub use service::PolicyStoreService;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockPolicyStoreProvider;
