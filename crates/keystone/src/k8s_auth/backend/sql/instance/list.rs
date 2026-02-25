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
//! List K8s auth instances

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{Cursor, SelectModel};

use crate::db::entity::kubernetes_auth_instance;
use crate::db::entity::prelude::KubernetesAuthInstance;
use crate::error::DbContextExt;
use crate::k8s_auth::{
    K8sAuthProviderError,
    types::{K8sAuthInstance, K8sAuthInstanceListParameters},
};

/// Prepare the query for listing k8s auth instances.
fn get_list_query(
    params: &K8sAuthInstanceListParameters,
) -> Result<Cursor<SelectModel<kubernetes_auth_instance::Model>>, K8sAuthProviderError> {
    let mut select = KubernetesAuthInstance::find();
    if let Some(val) = &params.domain_id {
        select = select.filter(kubernetes_auth_instance::Column::DomainId.eq(val));
    }
    if let Some(val) = &params.name {
        select = select.filter(kubernetes_auth_instance::Column::Name.eq(val));
    }

    Ok(select.cursor_by(kubernetes_auth_instance::Column::Id))
}

/// List K8s auth instances.
pub async fn list(
    db: &DatabaseConnection,
    params: &K8sAuthInstanceListParameters,
) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError> {
    Ok(get_list_query(params)?
        .all(db)
        .await
        .context("listing k8s auth instances")?
        .into_iter()
        .map(Into::into)
        .collect())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, Transaction, sea_query::*};

    use super::super::tests::get_k8s_auth_instance_mock;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "kubernetes_auth_instance"."ca_cert", "kubernetes_auth_instance"."disable_local_ca_jwt", "kubernetes_auth_instance"."domain_id", "kubernetes_auth_instance"."enabled", "kubernetes_auth_instance"."host", "kubernetes_auth_instance"."id", "kubernetes_auth_instance"."name" FROM "kubernetes_auth_instance""#,
            QueryOrder::query(
                &mut get_list_query(&K8sAuthInstanceListParameters::default()).unwrap()
            )
            .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_name() {
        assert!(
            QueryOrder::query(
                &mut get_list_query(&K8sAuthInstanceListParameters {
                    name: Some("name".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains("\"kubernetes_auth_instance\".\"name\" = 'name'")
        );
    }

    #[tokio::test]
    async fn test_query_domain_id() {
        let query = QueryOrder::query(
            &mut get_list_query(&K8sAuthInstanceListParameters {
                domain_id: Some("d1".into()),
                ..Default::default()
            })
            .unwrap(),
        )
        .to_string(PostgresQueryBuilder);
        assert!(query.contains("\"kubernetes_auth_instance\".\"domain_id\" = 'd1'"));
    }

    #[tokio::test]
    async fn test_list_no_params() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_k8s_auth_instance_mock("id1"),
                get_k8s_auth_instance_mock("id2"),
            ]])
            .into_connection();

        let res = list(&db, &K8sAuthInstanceListParameters::default())
            .await
            .unwrap();

        assert_eq!(2, res.len());
        assert!(res.contains(&K8sAuthInstance::from(get_k8s_auth_instance_mock("id1"))));

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "kubernetes_auth_instance"."ca_cert", "kubernetes_auth_instance"."disable_local_ca_jwt", "kubernetes_auth_instance"."domain_id", "kubernetes_auth_instance"."enabled", "kubernetes_auth_instance"."host", "kubernetes_auth_instance"."id", "kubernetes_auth_instance"."name" FROM "kubernetes_auth_instance" ORDER BY "kubernetes_auth_instance"."id" ASC"#,
                []
            ),]
        );
    }
}
