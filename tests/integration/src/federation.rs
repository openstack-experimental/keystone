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

mod identity_provider;

use std::pin::Pin;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::federation::*;

use crate::common::*;
use crate::impl_deleter;

impl_deleter!(
    Service,
    IdentityProvider,
    get_federation_provider,
    delete_identity_provider
);

pub async fn create_identity_provider(
    state: &ServiceState,
    data: IdentityProviderCreate,
) -> Result<AsyncResourceGuard<IdentityProvider, ServiceState>> {
    let res = state
        .provider
        .get_federation_provider()
        .create_identity_provider(&ExecutionContext::internal(state), data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
