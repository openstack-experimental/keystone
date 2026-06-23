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
use openstack_keystone_core::federation::FederationProviderError;

use crate::entity::prelude::{
    FederatedIdentityProvider as DbFederatedIdentityProvider,
    IdentityProvider as DbIdentityProvider,
};

/// Delete an identity provider by its ID.
///
/// Both the new-style and legacy table deletes are performed within a single
/// transaction so that a failure during the second delete does not leave orphan
/// data in the first table.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the identity provider to delete.
///
/// # Returns
/// A `Result` indicating success, or an `Error`.
pub async fn delete<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
) -> Result<(), FederationProviderError> {
    let id_str = id.as_ref();

    let txn = db
        .begin()
        .await
        .context("starting transaction for deleting identity provider")?;

    let res = DbFederatedIdentityProvider::delete_by_id(id_str)
        .exec(&txn)
        .await
        .context("deleting identity provider")?;

    if res.rows_affected == 1 {
        DbIdentityProvider::delete_by_id(id_str)
            .exec(&txn)
            .await
            .context("deleting v3 identity provider")?;
        txn.commit()
            .await
            .context("committing identity provider deletion transaction")?;
        Ok(())
    } else {
        txn.rollback()
            .await
            .context("rolling back identity provider deletion transaction")?;
        Err(FederationProviderError::IdentityProviderNotFound(
            id_str.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                },
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                },
                MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                },
            ])
            .into_connection();

        delete(&db, "id").await.unwrap();

        // Verify both tables were deleted inside a single transaction
        let txns = db.into_transaction_log();
        assert_eq!(txns.len(), 1);
        let sqls: Vec<&str> = txns[0]
            .statements()
            .iter()
            .map(|s| s.sql.as_str())
            .collect();
        assert!(sqls[0] == "BEGIN");
        assert!(sqls[1].contains("federated_identity_provider") && sqls[1].starts_with("DELETE"));
        assert!(sqls[2].contains("identity_provider") && sqls[2].starts_with("DELETE"));
        assert!(sqls[3] == "COMMIT");
    }
}
