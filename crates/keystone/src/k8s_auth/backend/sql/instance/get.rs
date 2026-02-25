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
//! Get existing k8s auth provider.
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use crate::db::entity::prelude::KubernetesAuthInstance;
use crate::error::DbContextExt;
use crate::k8s_auth::{K8sAuthProviderError, types::K8sAuthInstance};

/// Get existing k8s auth instance by the ID.
pub async fn get<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError> {
    Ok(KubernetesAuthInstance::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("reading kubernetes auth instance record")?
        .map(Into::into))
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_k8s_auth_instance_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_k8s_auth_instance_mock("id")]])
            .into_connection();

        assert_eq!(
            get(&db, "id").await.unwrap(),
            Some(get_k8s_auth_instance_mock("id").into())
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "kubernetes_auth_instance"."ca_cert", "kubernetes_auth_instance"."disable_local_ca_jwt", "kubernetes_auth_instance"."domain_id", "kubernetes_auth_instance"."enabled", "kubernetes_auth_instance"."host", "kubernetes_auth_instance"."id", "kubernetes_auth_instance"."name" FROM "kubernetes_auth_instance" WHERE "kubernetes_auth_instance"."id" = $1 LIMIT $2"#,
                ["id".into(), 1u64.into()]
            ),]
        );
    }
}
