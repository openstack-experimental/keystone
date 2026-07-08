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
//! SCIM realm provider integration tests (ADR 0024 §2), plus the Realm
//! Activation Gate (§2.B) and janitor purge (§6.C) driven over a real
//! Raft-backed backend.
//!
//! Raft-only backend — these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`), matching the `mapping`/`api_key`
//! test suites.

use eyre::Result;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::*;

mod create;
mod gate;
mod janitor;
mod list;
mod show;
mod update;

/// `ScimRealmApi` has no delete method (a realm is disabled via `update`,
/// never removed) so, unlike most resources in this test suite, there is no
/// `ResourceDeleter`/`AsyncResourceGuard` for `ScimRealmResource` — each
/// test's isolated per-test database makes cleanup unnecessary anyway.
pub async fn create_realm(
    state: &ServiceState,
    data: ScimRealmResourceCreate,
) -> Result<ScimRealmResource> {
    Ok(state
        .provider
        .get_scim_realm_provider()
        .create_realm(&ExecutionContext::internal(state), data)
        .await?)
}

/// Construct a sample realm creation payload for a given `(domain_id,
/// provider_id)` coordinate. `idp_id` is a placeholder id, matching the
/// provider-level `create_realm` path -- unlike the `/v4/scim_realms`
/// HTTP handler, the provider layer does not itself validate `idp_id`
/// against a real `IdentityProvider`.
pub fn sample_realm_create(domain_id: &str, provider_id: &str) -> ScimRealmResourceCreate {
    ScimRealmResourceCreate {
        domain_id: domain_id.to_string(),
        provider_id: provider_id.to_string(),
        idp_id: "test-idp".to_string(),
        display_name: "Integration test realm".to_string(),
    }
}
