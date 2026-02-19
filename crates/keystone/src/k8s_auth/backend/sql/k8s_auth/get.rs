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

use crate::db::entity::prelude::KubernetesAuth;
use crate::error::DbContextExt;
use crate::k8s_auth::{backend::error::K8sAuthDatabaseError, types::K8sAuthConfiguration};

/// Get existing k8s auth configuration by the ID.
pub async fn get<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
) -> Result<Option<K8sAuthConfiguration>, K8sAuthDatabaseError> {
    Ok(KubernetesAuth::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("reading kubernetes auth configuration record")?
        .map(Into::into))
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_k8s_auth_config_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_k8s_auth_config_mock("id")]])
            .into_connection();

        assert_eq!(
            get(&db, "id").await.unwrap(),
            Some(get_k8s_auth_config_mock("id").try_into().unwrap())
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "kubernetes_auth"."ca_cert", "kubernetes_auth"."domain_id", "kubernetes_auth"."enabled", "kubernetes_auth"."host", "kubernetes_auth"."id", "kubernetes_auth"."name" FROM "kubernetes_auth" WHERE "kubernetes_auth"."id" = $1 LIMIT $2"#,
                ["id".into(), 1u64.into()]
            ),]
        );
    }
}
