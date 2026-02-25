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
//! Get existing k8s auth configuration.
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use crate::db::entity::prelude::KubernetesAuthRole;
use crate::error::DbContextExt;
use crate::k8s_auth::{K8sAuthProviderError, types::K8sAuthRole};

/// Get existing k8s auth configuration by the ID.
pub async fn get<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
) -> Result<Option<K8sAuthRole>, K8sAuthProviderError> {
    Ok(KubernetesAuthRole::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("reading kubernetes auth role record")?
        .map(Into::into))
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_k8s_auth_role_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_k8s_auth_role_mock("id")]])
            .into_connection();

        assert_eq!(
            get(&db, "id").await.unwrap(),
            Some(get_k8s_auth_role_mock("id").into())
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "kubernetes_auth_role"."auth_instance_id", "kubernetes_auth_role"."bound_audience", "kubernetes_auth_role"."bound_service_account_names", "kubernetes_auth_role"."bound_service_account_namespaces", "kubernetes_auth_role"."domain_id", "kubernetes_auth_role"."id", "kubernetes_auth_role"."enabled", "kubernetes_auth_role"."name", "kubernetes_auth_role"."token_restriction_id" FROM "kubernetes_auth_role" WHERE "kubernetes_auth_role"."id" = $1 LIMIT $2"#,
                ["id".into(), 1u64.into()]
            ),]
        );
    }
}
