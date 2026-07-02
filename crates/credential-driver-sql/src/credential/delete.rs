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

use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;

use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};

/// Delete a credential by ID.
pub async fn delete(db: &DatabaseConnection, id: &str) -> Result<(), CredentialProviderError> {
    DbCredential::delete_many()
        .filter(db_credential::Column::Id.eq(id))
        .exec(db)
        .await
        .context("deleting credential")?;
    Ok(())
}

/// Delete all credentials owned by a user (identity lifecycle cascade).
pub async fn delete_for_user(
    db: &DatabaseConnection,
    user_id: &str,
) -> Result<(), CredentialProviderError> {
    DbCredential::delete_many()
        .filter(db_credential::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .context("deleting credentials for user")?;
    Ok(())
}

/// Delete all credentials bound to a project (identity lifecycle cascade;
/// primarily EC2 credentials).
pub async fn delete_for_project(
    db: &DatabaseConnection,
    project_id: &str,
) -> Result<(), CredentialProviderError> {
    DbCredential::delete_many()
        .filter(db_credential::Column::ProjectId.eq(project_id))
        .exec(db)
        .await
        .context("deleting credentials for project")?;
    Ok(())
}
