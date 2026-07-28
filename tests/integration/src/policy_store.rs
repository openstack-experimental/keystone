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
//! Legacy policy document store (`/v3/policies`) provider tests.

mod crud;

use std::pin::Pin;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::policy_store::*;

use crate::common::*;
use crate::impl_deleter;

impl_deleter!(Service, Policy, get_policy_store_provider, delete_policy);

/// Create a policy through the policy store provider, returning a guard that
/// deletes it again when dropped.
pub async fn create_policy(
    state: &ServiceState,
    data: PolicyCreate,
) -> Result<AsyncResourceGuard<Policy, ServiceState>> {
    let res = state
        .provider
        .get_policy_store_provider()
        .create_policy(&ExecutionContext::internal(state), data)
        .await?;
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
