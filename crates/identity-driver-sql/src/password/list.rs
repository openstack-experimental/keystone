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
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::{password, prelude::Password as DbPassword};

/// Lists passwords of the local user
///
/// # Parameters
/// - `db`: The database connection.
/// - `local_user_id`: The local user id.
///
///
/// # Returns
/// A `Result` containing a vector of passwords, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn list<C: ConnectionTrait>(
    db: &C,
    local_user_id: i32,
) -> Result<Vec<password::Model>, IdentityProviderError> {
    Ok(DbPassword::find()
        .filter(password::Column::LocalUserId.eq(local_user_id))
        .order_by(password::Column::CreatedAtInt, Order::Desc)
        .all(db)
        .await
        .context("listing local user passwords")?)
}
