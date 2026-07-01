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
//! # API Key (SCIM ingress) provider integration tests (ADR 0021)
//!
//! Raft-only backend — these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`), matching the `mapping`/`spiffe`
//! test suites.

use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use eyre::Result;

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core_types::api_key::*;

mod create;
mod get;
mod last_used;
mod list;
mod mapping_system_scope;
mod revoke;
mod update;

use crate::common::*;

impl ResourceDeleter<ApiClientResource> for Arc<Service> {
    fn delete(&self, resource: ApiClientResource) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            // No hard delete exists (ADR 0021 §5.C) — cleanup revokes instead.
            let _ = self
                .provider
                .get_api_key_provider()
                .revoke(
                    self,
                    &resource.domain_id,
                    &resource.client_id,
                    "test-cleanup",
                )
                .await;
        })
    }
}

pub async fn create_api_key(
    state: &ServiceState,
    data: ApiClientResourceCreate,
) -> Result<AsyncResourceGuard<ApiClientResource, ServiceState>> {
    let res = state
        .provider
        .get_api_key_provider()
        .create(state, data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}

/// Construct a sample API Key creation payload with unique `client_id` and
/// `lookup_hash` values. `secret_hash` is a well-formed-looking but
/// non-functional PHC string — provider-level CRUD does not perform Argon2id
/// verification, so it never needs to actually verify.
pub fn sample_api_key_create(domain_id: &str, provider_id: &str) -> ApiClientResourceCreate {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    ApiClientResourceCreate {
        domain_id: domain_id.to_string(),
        provider_id: provider_id.to_string(),
        client_id: format!("client-{unique}"),
        lookup_hash: format!("lookup-{unique}"),
        secret_hash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g".to_string(),
        allowed_ips: None,
        description: Some("integration test key".to_string()),
        expires_at: Utc::now().timestamp() + 3600,
    }
}
