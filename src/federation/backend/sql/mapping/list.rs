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
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{Cursor, SelectModel};

use crate::db::entity::{
    federated_mapping as db_federated_mapping, prelude::FederatedMapping as DbFederatedMapping,
    sea_orm_active_enums::MappingType as db_mapping_type,
};
use crate::error::DbContextExt;
use crate::federation::backend::error::FederationDatabaseError;
use crate::federation::types::*;

/// Prepare the paginated query for listing mappings.
fn get_list_query(
    params: &MappingListParameters,
) -> Result<Cursor<SelectModel<db_federated_mapping::Model>>, FederationDatabaseError> {
    let mut select = DbFederatedMapping::find();

    if let Some(val) = &params.name {
        select = select.filter(db_federated_mapping::Column::Name.eq(val));
    }

    if let Some(val) = &params.domain_id {
        select = select.filter(db_federated_mapping::Column::DomainId.eq(val));
    }

    if let Some(val) = &params.idp_id {
        select = select.filter(db_federated_mapping::Column::IdpId.eq(val));
    }

    if let Some(val) = &params.r#type {
        select = select.filter(db_federated_mapping::Column::r#Type.eq(db_mapping_type::from(val)));
    }

    let mut cursor = select.cursor_by(db_federated_mapping::Column::Id);
    if let Some(limit) = params.limit {
        cursor.first(limit);
    }
    if let Some(marker) = &params.marker {
        cursor.after(marker);
    }
    Ok(cursor)
}

pub async fn list(
    db: &DatabaseConnection,
    params: &MappingListParameters,
) -> Result<Vec<Mapping>, FederationDatabaseError> {
    get_list_query(params)?
        .all(db)
        .await
        .context("listing attribute mappings")?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, Transaction, sea_query::*};

    use super::super::tests::get_mapping_mock;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", CAST("federated_mapping"."type" AS "text"), "federated_mapping"."enabled", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_id_claim", "federated_mapping"."user_name_claim", "federated_mapping"."domain_id_claim", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."token_project_id", "federated_mapping"."token_restriction_id" FROM "federated_mapping""#,
            QueryOrder::query(&mut get_list_query(&MappingListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_name() {
        assert!(
            QueryOrder::query(
                &mut get_list_query(&MappingListParameters {
                    name: Some("name".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains("\"federated_mapping\".\"name\" = 'name'")
        );
    }

    #[tokio::test]
    async fn test_query_domain_id() {
        let query = QueryOrder::query(
            &mut get_list_query(&MappingListParameters {
                domain_id: Some("idp_id".into()),
                ..Default::default()
            })
            .unwrap(),
        )
        .to_string(PostgresQueryBuilder);
        assert!(query.contains("\"federated_mapping\".\"domain_id\" = 'idp_id'"),);
    }

    #[tokio::test]
    async fn test_query_type() {
        assert!(
            QueryOrder::query(
                &mut get_list_query(&MappingListParameters {
                    r#type: Some(MappingType::Jwt),
                    ..Default::default()
                })
                .unwrap(),
            )
            .to_string(PostgresQueryBuilder)
            .contains(
                "\"federated_mapping\".\"type\" = (CAST('jwt' AS \"federated_mapping_type\"))"
            ),
        );
    }

    #[tokio::test]
    async fn test_list_no_params() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")]])
            .into_connection();

        assert_eq!(
            list(&db, &MappingListParameters::default()).await.unwrap(),
            vec![Mapping {
                id: "1".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                idp_id: "idp".into(),
                enabled: true,
                user_id_claim: "sub".into(),
                user_name_claim: "preferred_username".into(),
                domain_id_claim: Some("domain_id".into()),
                ..Default::default()
            }]
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", CAST("federated_mapping"."type" AS "text"), "federated_mapping"."enabled", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_id_claim", "federated_mapping"."user_name_claim", "federated_mapping"."domain_id_claim", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."token_project_id", "federated_mapping"."token_restriction_id" FROM "federated_mapping" ORDER BY "federated_mapping"."id" ASC"#,
                []
            ),]
        );
    }

    #[tokio::test]
    async fn test_list_all_params() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")]])
            .into_connection();

        assert!(
            list(
                &db,
                &MappingListParameters {
                    name: Some("mapping_name".into()),
                    domain_id: Some("did".into()),
                    idp_id: Some("idp".into()),
                    r#type: Some(MappingType::Jwt),
                    limit: Some(7),
                    marker: Some("marker".into()),
                }
            )
            .await
            .is_ok()
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", CAST("federated_mapping"."type" AS "text"), "federated_mapping"."enabled", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_id_claim", "federated_mapping"."user_name_claim", "federated_mapping"."domain_id_claim", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."token_project_id", "federated_mapping"."token_restriction_id" FROM "federated_mapping" WHERE "federated_mapping"."name" = $1 AND "federated_mapping"."domain_id" = $2 AND "federated_mapping"."idp_id" = $3 AND "federated_mapping"."type" = (CAST($4 AS "federated_mapping_type")) AND "federated_mapping"."id" > $5 ORDER BY "federated_mapping"."id" ASC LIMIT $6"#,
                [
                    "mapping_name".into(),
                    "did".into(),
                    "idp".into(),
                    "jwt".into(),
                    "marker".into(),
                    7u64.into()
                ]
            ),]
        );
    }
}
