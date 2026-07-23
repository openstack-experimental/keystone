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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::trust::TrustProviderError;

use crate::entity::prelude::Trust as DbTrust;

/// Soft-delete the trust by ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the trust to delete.
pub async fn delete<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<(), TrustProviderError> {
    if let Some(entry) = DbTrust::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching trust by id")?
    {
        let mut model: crate::entity::trust::ActiveModel = entry.into();
        model.deleted_at = Set(Some(chrono::Utc::now().naive_utc()));
        model.update(db).await.context("soft-deleting trust")?;
    } else {
        return Err(TrustProviderError::TrustNotFound(id.as_ref().to_string()));
    }
    Ok(())
}
