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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::RoleOptions;

use crate::entity::{prelude::RoleOption as DbRoleOption, role_option};

/// List options of a role by its ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `role_id`: The role ID.
///
/// # Returns
/// A `Result` containing `RoleOptions` if successful, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn list_by_role_id<C, S>(db: &C, role_id: S) -> Result<RoleOptions, RoleProviderError>
where
    C: ConnectionTrait,
    S: AsRef<str>,
{
    Ok(RoleOptions::from_iter(
        DbRoleOption::find()
            .filter(role_option::Column::RoleId.eq(role_id.as_ref()))
            .all(db)
            .await
            .context("fetching options of the role")?,
    ))
}
