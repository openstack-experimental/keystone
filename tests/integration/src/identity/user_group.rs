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

use eyre::Report;

use openstack_keystone_core::identity::IdentityApi;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::identity::*;

mod add;
mod list;

async fn list_user_groups<U>(state: &ServiceState, user_id: U) -> Result<Vec<Group>, Report>
where
    U: AsRef<str>,
{
    Ok(state
        .provider
        .get_identity_provider()
        .list_groups_of_user(state, user_id.as_ref())
        .await?
        .into_iter()
        .collect())
}
