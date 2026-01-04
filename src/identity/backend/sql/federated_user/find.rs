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

use crate::db::entity::{federated_user, prelude::FederatedUser};
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;

/// Get federated user entry by the idp_id and the unique_id
pub async fn find_by_idp_and_unique_id<I: AsRef<str>, U: AsRef<str>>(
    db: &DatabaseConnection,
    idp_id: I,
    unique_id: U,
) -> Result<Option<federated_user::Model>, IdentityDatabaseError> {
    Ok(FederatedUser::find()
        .filter(federated_user::Column::IdpId.eq(idp_id.as_ref()))
        .filter(federated_user::Column::UniqueId.eq(unique_id.as_ref()))
        .all(db)
        .await
        .context("searching federated user by the idp and unique id")?
        .first()
        .cloned())
}

#[cfg(test)]
mod tests {}
