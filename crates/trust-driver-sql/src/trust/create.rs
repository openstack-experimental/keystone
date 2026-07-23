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
use sea_orm::TransactionTrait;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::trust::TrustProviderError;
use openstack_keystone_core_types::trust::*;

use crate::entity::{
    prelude::TrustRole as DbTrustRole, trust as db_trust, trust_role as db_trust_role,
};

impl TryFrom<TrustCreate> for db_trust::ActiveModel {
    type Error = TrustProviderError;

    fn try_from(value: TrustCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            // The trust id is always populated by `TrustService::create_trust`
            // before the backend is invoked.
            id: Set(value.id.unwrap_or_default()),
            trustor_user_id: Set(value.trustor_user_id),
            trustee_user_id: Set(value.trustee_user_id),
            project_id: Set(value.project_id),
            impersonation: Set(value.impersonation),
            deleted_at: NotSet,
            expires_at: NotSet,
            remaining_uses: Set(value.remaining_uses),
            extra: Set(value.extra.map(|v| serde_json::to_string(&v)).transpose()?),
            expires_at_int: Set(value.expires_at.map(|v| v.timestamp_micros())),
            redelegated_trust_id: Set(value.redelegated_trust_id),
            redelegation_count: Set(value.redelegation_count),
        })
    }
}

/// Create the trust.
///
/// # Parameters
/// - `db`: The database connection.
/// - `rec`: The trust to create.
///
/// # Returns
/// A `Result` containing the created `Trust` or an `Error`.
pub async fn create(
    db: &DatabaseConnection,
    rec: TrustCreate,
) -> Result<Trust, TrustProviderError> {
    let txn = db
        .begin()
        .await
        .context("starting transaction for persisting trust")?;

    let roles = rec.roles.clone();
    let model = db_trust::ActiveModel::try_from(rec)?;

    let db_entry = model.insert(&txn).await.context("persisting trust")?;

    if !roles.is_empty() {
        DbTrustRole::insert_many(roles.iter().map(|role| db_trust_role::ActiveModel {
            trust_id: Set(db_entry.id.clone()),
            role_id: Set(role.id.clone()),
        }))
        .exec(&txn)
        .await
        .context("persisting trust role relations")?;
    }

    txn.commit()
        .await
        .context("committing transaction for persisting trust")?;

    let mut trust: Trust = db_entry.try_into()?;
    if !roles.is_empty() {
        trust.roles = Some(roles);
    }
    Ok(trust)
}
