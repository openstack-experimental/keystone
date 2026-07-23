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

mod create;
mod delete;
mod get;
mod list;

use std::pin::Pin;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::trust::*;

use crate::common::*;
use crate::impl_deleter;

impl_deleter!(Service, Trust, get_trust_provider, delete_trust);

/// Create a trust through the trust provider, returning a guard that deletes
/// it again when dropped.
pub async fn create_trust(
    state: &ServiceState,
    data: TrustCreate,
) -> Result<AsyncResourceGuard<Trust, ServiceState>> {
    let res = state
        .provider
        .get_trust_provider()
        .create_trust(&ExecutionContext::internal(state), data)
        .await?;
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
