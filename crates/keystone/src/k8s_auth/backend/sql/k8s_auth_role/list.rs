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
//! List K8s auth configurations

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{Cursor, SelectModel};

use crate::db::entity::kubernetes_auth_role;
use crate::db::entity::prelude::KubernetesAuthRole;
use crate::error::DbContextExt;
use crate::k8s_auth::{
    K8sAuthProviderError,
    types::{K8sAuthRole, K8sAuthRoleListParameters},
};

/// Prepare the query for listing k8s auth roles.
fn get_list_query(
    params: &K8sAuthRoleListParameters,
) -> Result<Cursor<SelectModel<kubernetes_auth_role::Model>>, K8sAuthProviderError> {
    let mut select = KubernetesAuthRole::find();
    if let Some(val) = &params.auth_configuration_id {
        select = select.filter(kubernetes_auth_role::Column::AuthConfigurationId.eq(val));
    }
    if let Some(val) = &params.domain_id {
        select = select.filter(kubernetes_auth_role::Column::DomainId.eq(val));
    }
    if let Some(val) = &params.name {
        select = select.filter(kubernetes_auth_role::Column::Name.eq(val));
    }

    Ok(select.cursor_by(kubernetes_auth_role::Column::Id))
}

/// List K8s auth roles.
pub async fn list(
    db: &DatabaseConnection,
    params: &K8sAuthRoleListParameters,
) -> Result<Vec<K8sAuthRole>, K8sAuthProviderError> {
    Ok(get_list_query(params)?
        .all(db)
        .await
        .context("listing k8s auth roles")?
        .into_iter()
        .map(Into::into)
        .collect())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, Transaction, sea_query::*};

    use super::super::tests::get_k8s_auth_role_mock;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "kubernetes_auth_role"."auth_configuration_id", "kubernetes_auth_role"."bound_audience", "kubernetes_auth_role"."bound_service_account_names", "kubernetes_auth_role"."bound_service_account_namespaces", "kubernetes_auth_role"."domain_id", "kubernetes_auth_role"."id", "kubernetes_auth_role"."enabled", "kubernetes_auth_role"."name", "kubernetes_auth_role"."token_restriction_id" FROM "kubernetes_auth_role""#,
            QueryOrder::query(&mut get_list_query(&K8sAuthRoleListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_name() {
        assert!(
            QueryOrder::query(
                &mut get_list_query(&K8sAuthRoleListParameters {
                    name: Some("name".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains("\"kubernetes_auth_role\".\"name\" = 'name'")
        );
    }

    #[tokio::test]
    async fn test_query_domain_id() {
        let query = QueryOrder::query(
            &mut get_list_query(&K8sAuthRoleListParameters {
                domain_id: Some("d1".into()),
                ..Default::default()
            })
            .unwrap(),
        )
        .to_string(PostgresQueryBuilder);
        assert!(query.contains("\"kubernetes_auth_role\".\"domain_id\" = 'd1'"));
    }

    #[tokio::test]
    async fn test_query_configuration_id() {
        let query = QueryOrder::query(
            &mut get_list_query(&K8sAuthRoleListParameters {
                auth_configuration_id: Some("cid".into()),
                ..Default::default()
            })
            .unwrap(),
        )
        .to_string(PostgresQueryBuilder);
        assert!(query.contains("\"kubernetes_auth_role\".\"auth_configuration_id\" = 'cid'"));
    }

    #[tokio::test]
    async fn test_list_no_params() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_k8s_auth_role_mock("id1"),
                get_k8s_auth_role_mock("id2"),
            ]])
            .into_connection();

        let res = list(&db, &K8sAuthRoleListParameters::default())
            .await
            .unwrap();

        assert_eq!(2, res.len());
        assert!(res.contains(&K8sAuthRole::from(get_k8s_auth_role_mock("id1"))));
        assert!(res.contains(&K8sAuthRole::from(get_k8s_auth_role_mock("id2"))));

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "kubernetes_auth_role"."auth_configuration_id", "kubernetes_auth_role"."bound_audience", "kubernetes_auth_role"."bound_service_account_names", "kubernetes_auth_role"."bound_service_account_namespaces", "kubernetes_auth_role"."domain_id", "kubernetes_auth_role"."id", "kubernetes_auth_role"."enabled", "kubernetes_auth_role"."name", "kubernetes_auth_role"."token_restriction_id" FROM "kubernetes_auth_role" ORDER BY "kubernetes_auth_role"."id" ASC"#,
                []
            ),]
        );
    }
}
