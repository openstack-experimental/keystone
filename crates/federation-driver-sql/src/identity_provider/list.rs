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
//! # List federated identity providers
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{Cursor, SelectModel};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::federation::FederationProviderError;
use openstack_keystone_core_types::federation::*;

use crate::entity::{
    federated_identity_provider as db_federated_identity_provider,
    prelude::FederatedIdentityProvider as DbFederatedIdentityProvider,
};

/// Prepare the paginated query for listing identity providers.
///
/// # Parameters
/// - `params`: The parameters for listing identity providers.
///
/// # Returns
/// A `Result` containing the paginated query cursor, or an `Error`.
fn get_list_query(
    params: &IdentityProviderListParameters,
) -> Result<Cursor<SelectModel<db_federated_identity_provider::Model>>, FederationProviderError> {
    let mut select = DbFederatedIdentityProvider::find();

    if let Some(val) = &params.name {
        select = select.filter(db_federated_identity_provider::Column::Name.eq(val));
    }

    if let Some(val) = &params.domain_ids {
        let filter = db_federated_identity_provider::Column::DomainId.is_in(val.iter().flatten());
        select = if val.contains(&None) {
            select.filter(
                Condition::any()
                    .add(filter)
                    .add(db_federated_identity_provider::Column::DomainId.is_null()),
            )
        } else {
            select.filter(filter)
        };
    }

    let mut cursor = select.cursor_by(db_federated_identity_provider::Column::Id);
    if let Some(limit) = params.limit {
        cursor.first(limit);
    }
    if let Some(marker) = &params.marker {
        cursor.after(marker);
    }
    Ok(cursor)
}

/// List federated identity providers.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters for listing identity providers.
///
/// # Returns
/// A `Result` containing a list of `IdentityProvider` objects, or an `Error`.
pub async fn list(
    db: &DatabaseConnection,
    params: &IdentityProviderListParameters,
) -> Result<Vec<IdentityProvider>, FederationProviderError> {
    get_list_query(params)?
        .all(db)
        .await
        .context("listing identity providers")?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, sea_query::*};
    use std::collections::HashSet;

    use super::super::tests::get_idp_mock;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        let sql = QueryOrder::query(
            &mut get_list_query(&IdentityProviderListParameters::default()).unwrap(),
        )
        .to_string(PostgresQueryBuilder);
        assert!(sql.starts_with("SELECT"));
        assert!(sql.contains("federated_identity_provider"));
        assert!(sql.ends_with(r#"FROM "federated_identity_provider""#));
    }

    #[tokio::test]
    async fn test_query_name() {
        assert!(
            QueryOrder::query(
                &mut get_list_query(&IdentityProviderListParameters {
                    name: Some("idp_name".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains("\"federated_identity_provider\".\"name\" = 'idp_name'")
        );
    }

    #[tokio::test]
    async fn test_query_domain_ids() {
        let query = QueryOrder::query(
            &mut get_list_query(&IdentityProviderListParameters {
                domain_ids: Some(HashSet::from([Some("d1".into()), Some("d2".into()), None])),
                ..Default::default()
            })
            .unwrap(),
        )
        .to_string(PostgresQueryBuilder);
        assert!(
            query.contains("\"federated_identity_provider\".\"domain_id\" IN (")
                && query.contains("'d1'")
                && query.contains("'d2'")
                && query.contains(") OR \"federated_identity_provider\".\"domain_id\" IS NULL"),
            "domain_id filter in in {}",
            query
        );
    }

    #[tokio::test]
    async fn test_list_no_params() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();
        // `IdentityProvider` is not `PartialEq` (secret field), so assert per
        // field on the single returned entry.
        let idps = list(&db, &IdentityProviderListParameters::default())
            .await
            .unwrap();
        assert_eq!(idps.len(), 1);
        assert_eq!(idps[0].id, "1");
        assert_eq!(idps[0].name, "name");
        assert_eq!(idps[0].domain_id, Some("did".into()));

        // Checking transaction log: single SELECT from the right table
        let txns = db.into_transaction_log();
        assert_eq!(txns.len(), 1);
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.starts_with("SELECT"));
        assert!(sql.contains("federated_identity_provider"));
        assert!(sql.contains(r#"ORDER BY "federated_identity_provider"."id" ASC"#));
    }

    #[tokio::test]
    async fn test_list_all_params() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();

        let idps = list(
            &db,
            &IdentityProviderListParameters {
                name: Some("idp_name".into()),
                domain_ids: Some(HashSet::from([Some("did".into())])),
                limit: Some(1),
                marker: Some("marker".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(idps.len(), 1);
        assert_eq!(idps[0].id, "1");
        assert_eq!(idps[0].name, "name");
        assert_eq!(idps[0].domain_id, Some("did".into()));

        // Checking transaction log: single SELECT with correct filters
        let txns = db.into_transaction_log();
        assert_eq!(txns.len(), 1);
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.starts_with("SELECT"));
        assert!(sql.contains("federated_identity_provider"));
        assert!(sql.contains(r#""federated_identity_provider"."name" ="#));
        assert!(sql.contains(r#""federated_identity_provider"."domain_id" IN"#));
        assert!(sql.contains(r#""federated_identity_provider"."id" >"#));
        assert!(sql.contains(r#"ORDER BY "federated_identity_provider"."id" ASC"#));
        assert!(sql.contains("LIMIT"));
    }
}
