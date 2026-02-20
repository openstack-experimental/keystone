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

use crate::db::entity::prelude::KubernetesAuthRole;
use crate::error::DbContextExt;
use crate::k8s_auth::{
    K8sAuthProviderError,
    types::{K8sAuthRole, K8sAuthRoleUpdate},
};

/// Update existing k8s auth role by the ID.
///
/// Perform search and update of the k8s auth role in an isolated transaction.
pub async fn update<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
    data: K8sAuthRoleUpdate,
) -> Result<K8sAuthRole, K8sAuthProviderError> {
    // Start transaction to prevent TOCTOU
    let txn = db
        .begin()
        .await
        .context("starting transaction for updating k8s auth role")?;
    let res = if let Some(current) = KubernetesAuthRole::find_by_id(id.as_ref())
        .one(&txn)
        .await
        .context("searching for the existing k8s auth role")?
    {
        Ok(current
            .to_active_model_update(data)
            .update(&txn)
            .await
            .context("updating k8s auth role")?
            .into())
    } else {
        Err(K8sAuthProviderError::RoleNotFound(id.as_ref().to_string()))
    };
    txn.commit()
        .await
        .context("committing the k8s auth role update transaction")?;
    res
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Statement, Transaction};

    use super::super::tests::get_k8s_auth_role_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_k8s_auth_role_mock("id1")]])
            .append_query_results([vec![get_k8s_auth_role_mock("id1")]])
            .into_connection();

        let req = K8sAuthRoleUpdate {
            bound_audience: Some("new_aud".into()),
            bound_service_account_names: Some(vec!["c".into()]),
            bound_service_account_namespaces: Some(vec!["nc".into()]),
            enabled: Some(true),
            name: Some("new_name".into()),
            token_restriction_id: Some("new_trid".into()),
        };

        update(&db, "id1", req).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#,),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "kubernetes_auth_role"."auth_configuration_id", "kubernetes_auth_role"."bound_audience", "kubernetes_auth_role"."bound_service_account_names", "kubernetes_auth_role"."bound_service_account_namespaces", "kubernetes_auth_role"."domain_id", "kubernetes_auth_role"."id", "kubernetes_auth_role"."enabled", "kubernetes_auth_role"."name", "kubernetes_auth_role"."token_restriction_id" FROM "kubernetes_auth_role" WHERE "kubernetes_auth_role"."id" = $1 LIMIT $2"#,
                    ["id1".into(), 1u64.into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "kubernetes_auth_role" SET "bound_audience" = $1, "bound_service_account_names" = $2, "bound_service_account_namespaces" = $3, "enabled" = $4, "name" = $5, "token_restriction_id" = $6 WHERE "kubernetes_auth_role"."id" = $7 RETURNING "auth_configuration_id", "bound_audience", "bound_service_account_names", "bound_service_account_namespaces", "domain_id", "id", "enabled", "name", "token_restriction_id""#,
                    [
                        "new_aud".into(),
                        "c".into(),
                        "nc".into(),
                        true.into(),
                        "new_name".into(),
                        "new_trid".into(),
                        "id1".into(),
                    ]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#,)
            ])]
        );
    }
}
