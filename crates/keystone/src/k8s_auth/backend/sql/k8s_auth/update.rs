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
//! Update the existing K8s auth configuration

use sea_orm::DatabaseConnection;
use sea_orm::TransactionTrait;
use sea_orm::entity::*;

use crate::db::entity::prelude::KubernetesAuth;
use crate::error::DbContextExt;
use crate::k8s_auth::{
    backend::error::K8sAuthDatabaseError,
    types::{K8sAuthConfiguration, K8sAuthConfigurationUpdate},
};

/// Update existing k8s auth configuration by the ID.
///
/// Perform search and update of the k8s auth configuration in an isolated
/// transaction.
pub async fn update<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
    data: K8sAuthConfigurationUpdate,
) -> Result<K8sAuthConfiguration, K8sAuthDatabaseError> {
    // Start transaction to prevent TOCTOU
    let txn = db
        .begin()
        .await
        .context("starting transaction for updating k8s auth configuration")?;
    let res = if let Some(current) = KubernetesAuth::find_by_id(id.as_ref())
        .one(&txn)
        .await
        .context("searching for the existing k8s auth configuration for update")?
    {
        Ok(current
            .to_active_model_update(data)
            .update(&txn)
            .await
            .context("updating k8s auth configuration")?
            .into())
    } else {
        Err(K8sAuthDatabaseError::ConfigurationNotFound(
            id.as_ref().to_string(),
        ))
    };
    txn.commit()
        .await
        .context("committing the k8s auth configuration update transaction")?;
    res
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Statement, Transaction};

    use super::super::tests::get_k8s_auth_config_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_k8s_auth_config_mock("id1")]])
            .append_query_results([vec![get_k8s_auth_config_mock("id1")]])
            .into_connection();

        let req = K8sAuthConfigurationUpdate {
            ca_cert: Some("new_ca".into()),
            enabled: Some(true),
            host: Some("new_host".into()),
            name: Some("new_name".into()),
        };

        update(&db, "id1", req).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#,),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "kubernetes_auth"."ca_cert", "kubernetes_auth"."domain_id", "kubernetes_auth"."enabled", "kubernetes_auth"."host", "kubernetes_auth"."id", "kubernetes_auth"."name" FROM "kubernetes_auth" WHERE "kubernetes_auth"."id" = $1 LIMIT $2"#,
                    ["id1".into(), 1u64.into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "kubernetes_auth" SET "ca_cert" = $1, "enabled" = $2, "host" = $3, "name" = $4 WHERE "kubernetes_auth"."id" = $5 RETURNING "ca_cert", "domain_id", "enabled", "host", "id", "name""#,
                    [
                        "new_ca".into(),
                        true.into(),
                        "new_host".into(),
                        "new_name".into(),
                        "id1".into(),
                    ]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#,)
            ])]
        );
    }
}
