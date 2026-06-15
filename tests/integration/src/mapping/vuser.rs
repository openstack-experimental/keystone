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

use openstack_keystone::keystone::Service;
use openstack_keystone_core::mapping::MappingApi;
use openstack_keystone_core_types::mapping::VirtualUser;

mod delete;
mod get;
mod lifecycle;

use crate::common::*;

impl ResourceDeleter<VirtualUser> for Arc<Service> {
    fn delete(&self, resource: VirtualUser) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let _ = self
                .provider
                .get_mapping_provider()
                .delete_virtual_user(self, &resource.user_id)
                .await;
        })
    }
}
