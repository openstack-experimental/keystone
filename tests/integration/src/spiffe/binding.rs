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

use std::pin::Pin;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::spiffe::SpiffeApi;
use openstack_keystone_core_types::spiffe::*;

mod create;
mod delete;
mod get;
mod list;
mod update;

use crate::common::*;

impl ResourceDeleter<SpiffeBinding> for Arc<Service> {
    fn delete(&self, resource: SpiffeBinding) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let _ = self
                .provider
                .get_spiffe_provider()
                .delete_binding(self, &resource.svid)
                .await;
        })
    }
}

pub async fn create_binding(
    state: &ServiceState,
    data: SpiffeBindingCreate,
) -> Result<AsyncResourceGuard<SpiffeBinding, ServiceState>> {
    let res = state
        .provider
        .get_spiffe_provider()
        .create_binding(state, data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
