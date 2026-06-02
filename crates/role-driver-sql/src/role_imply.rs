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

use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::{RoleImply, RoleImplyBuilder};

mod create;
mod delete;
mod get;
mod list;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::list;

use crate::entity::implied_role as db_implied_role;

impl TryFrom<db_implied_role::Model> for RoleImply {
    type Error = RoleProviderError;

    fn try_from(value: db_implied_role::Model) -> Result<Self, Self::Error> {
        Ok(RoleImplyBuilder::default()
            .id(value.prior_role_id)
            .implies_role_id(value.implied_role_id)
            .build()?)
    }
}
