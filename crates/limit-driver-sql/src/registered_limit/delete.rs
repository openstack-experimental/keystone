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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::limit::LimitProviderError;

use crate::entity::prelude::RegisteredLimit as DbRegisteredLimit;
use crate::entity::registered_limit as db_registered_limit;
use crate::registered_limit::ensure_not_referenced;

/// Delete the registered limit.
///
/// A registered limit referenced by limits can not be deleted.
pub async fn delete<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<(), LimitProviderError> {
    let id = id.as_ref();
    let txn = db.begin().await.context("starting transaction")?;
    ensure_not_referenced(&txn, id).await?;
    let res = DbRegisteredLimit::delete_many()
        .filter(db_registered_limit::Column::Id.eq(id))
        .exec(&txn)
        .await
        .context("deleting registered limit")?;
    if res.rows_affected == 0 {
        return Err(LimitProviderError::RegisteredLimitNotFound(id.to_string()));
    }
    txn.commit().await.context("committing transaction")?;
    Ok(())
}
