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

use crate::db::entity::{
    federated_mapping as db_federated_mapping, prelude::FederatedMapping as DbFederatedMapping,
    sea_orm_active_enums::MappingType as db_mapping_type,
};
use crate::federation::backend::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn list(
    db: &DatabaseConnection,
    params: &MappingListParameters,
) -> Result<Vec<Mapping>, FederationDatabaseError> {
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

    let db_entities: Vec<db_federated_mapping::Model> = select
        .all(db)
        .await
        .map_err(|err| db_err(err, "fetching mappings"))?;
    let results: Result<Vec<Mapping>, _> = db_entities
        .into_iter()
        .map(TryInto::<Mapping>::try_into)
        .collect();

    results
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_mapping_mock;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")]])
            .append_query_results([vec![get_mapping_mock("1")]])
            .into_connection();

        assert!(list(&db, &MappingListParameters::default()).await.is_ok());
        assert_eq!(
            list(
                &db,
                &MappingListParameters {
                    name: Some("mapping_name".into()),
                    domain_id: Some("did".into()),
                    idp_id: Some("idp".into()),
                    r#type: Some(MappingType::Jwt)
                }
            )
            .await
            .unwrap(),
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
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", CAST("federated_mapping"."type" AS "text"), "federated_mapping"."enabled", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_id_claim", "federated_mapping"."user_name_claim", "federated_mapping"."domain_id_claim", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."token_project_id", "federated_mapping"."token_restriction_id" FROM "federated_mapping""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", CAST("federated_mapping"."type" AS "text"), "federated_mapping"."enabled", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_id_claim", "federated_mapping"."user_name_claim", "federated_mapping"."domain_id_claim", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."token_project_id", "federated_mapping"."token_restriction_id" FROM "federated_mapping" WHERE "federated_mapping"."name" = $1 AND "federated_mapping"."domain_id" = $2 AND "federated_mapping"."idp_id" = $3 AND "federated_mapping"."type" = (CAST($4 AS "federated_mapping_type"))"#,
                    [
                        "mapping_name".into(),
                        "did".into(),
                        "idp".into(),
                        "jwt".into()
                    ]
                ),
            ]
        );
    }
}
