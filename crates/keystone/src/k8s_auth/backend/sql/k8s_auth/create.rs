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
//! Create K8s auth configuration

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use crate::db::entity::kubernetes_auth;
use crate::error::DbContextExt;
use crate::k8s_auth::{
    K8sAuthProviderError,
    types::{K8sAuthConfiguration, K8sAuthConfigurationCreate},
};

/// Create new k8s auth configuration.
pub async fn create(
    db: &DatabaseConnection,
    data: K8sAuthConfigurationCreate,
) -> Result<K8sAuthConfiguration, K8sAuthProviderError> {
    Ok(kubernetes_auth::ActiveModel::from(data)
        .insert(db)
        .await
        .context("creating k8s auth configuration")?
        .into())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_k8s_auth_config_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_k8s_auth_config_mock("1")]])
            .into_connection();

        let cid = uuid::Uuid::new_v4().simple().to_string();
        let req = K8sAuthConfigurationCreate {
            ca_cert: Some("ca_cert".into()),
            domain_id: "did".into(),
            enabled: true,
            host: "host".into(),
            id: Some(cid.clone()),
            name: Some("name".into()),
        };

        create(&db, req).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "kubernetes_auth" ("ca_cert", "domain_id", "enabled", "host", "id", "name") VALUES ($1, $2, $3, $4, $5, $6) RETURNING "ca_cert", "domain_id", "enabled", "host", "id", "name""#,
                [
                    "ca_cert".into(),
                    "did".into(),
                    true.into(),
                    "host".into(),
                    cid.into(),
                    "name".into()
                ]
            ),]
        );
    }
}
