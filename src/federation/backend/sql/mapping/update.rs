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

use crate::db::entity::{
    federated_mapping as db_federated_mapping, prelude::FederatedMapping as DbFederatedMapping,
};
use crate::federation::backend::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn update<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
    mapping: MappingUpdate,
) -> Result<Mapping, FederationDatabaseError> {
    if let Some(current) = DbFederatedMapping::find_by_id(id.as_ref())
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching mapping by id for update"))?
    {
        let mut entry: db_federated_mapping::ActiveModel = current.into();
        if let Some(val) = mapping.name {
            entry.name = Set(val.to_owned());
        }
        if let Some(val) = mapping.idp_id {
            entry.idp_id = Set(val.to_owned());
        }
        if let Some(val) = mapping.r#type {
            entry.r#type = Set(val.into());
        }
        if let Some(val) = mapping.enabled {
            entry.enabled = Set(val);
        }
        if let Some(val) = mapping.allowed_redirect_uris {
            entry.allowed_redirect_uris = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = mapping.user_id_claim {
            entry.user_id_claim = Set(val.to_owned());
        }
        if let Some(val) = mapping.user_name_claim {
            entry.user_name_claim = Set(val.to_owned());
        }
        if let Some(val) = mapping.domain_id_claim {
            entry.domain_id_claim = Set(Some(val.to_owned()));
        }
        if let Some(val) = mapping.groups_claim {
            entry.groups_claim = Set(val.to_owned());
        }
        if let Some(val) = mapping.bound_audiences {
            entry.bound_audiences = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = mapping.bound_subject {
            entry.bound_subject = Set(val.to_owned());
        }
        if let Some(val) = &mapping.bound_claims {
            entry.bound_claims = Set(Some(val.clone()));
        }
        if let Some(val) = mapping.oidc_scopes {
            entry.oidc_scopes = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = mapping.token_project_id {
            entry.token_project_id = Set(val.to_owned());
        }
        if let Some(val) = mapping.token_restriction_id {
            entry.token_restriction_id = Set(Some(val.to_owned()));
        }

        let db_entry: db_federated_mapping::Model = entry
            .update(db)
            .await
            .map_err(|err| db_err(err, "updating the mapping"))?;
        db_entry.try_into()
    } else {
        Err(FederationDatabaseError::MappingNotFound(
            id.as_ref().to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
    use serde_json::json;

    use super::super::tests::get_mapping_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")], vec![get_mapping_mock("1")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        let req = MappingUpdate {
            name: Some("name".into()),
            idp_id: Some("idp".into()),
            r#type: MappingType::default().into(),
            enabled: Some(true),
            allowed_redirect_uris: Some(Some(vec!["url".into()])),
            user_id_claim: Some("sub".into()),
            user_name_claim: Some("preferred_username".into()),
            domain_id_claim: Some("domain_id".into()),
            groups_claim: Some(Some("groups".into())),
            bound_audiences: Some(Some(vec!["a1".into(), "a2".into()])),
            bound_subject: Some(Some("subject".into())),
            bound_claims: Some(json!({"department": "foo"})),
            //claim_mappings: Some(json!({"foo": "bar"})),
            oidc_scopes: Some(Some(vec!["oidc".into(), "oauth".into()])),
            token_project_id: Some(Some("pid".into())),
            token_restriction_id: Some("trid".into()),
        };

        assert_eq!(
            update(&db, "1", req).await.unwrap(),
            get_mapping_mock("1").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", CAST("federated_mapping"."type" AS "text"), "federated_mapping"."enabled", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_id_claim", "federated_mapping"."user_name_claim", "federated_mapping"."domain_id_claim", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."token_project_id", "federated_mapping"."token_restriction_id" FROM "federated_mapping" WHERE "federated_mapping"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "federated_mapping" SET "name" = $1, "idp_id" = $2, "type" = CAST($3 AS "federated_mapping_type"), "enabled" = $4, "allowed_redirect_uris" = $5, "user_id_claim" = $6, "user_name_claim" = $7, "domain_id_claim" = $8, "groups_claim" = $9, "bound_audiences" = $10, "bound_subject" = $11, "bound_claims" = $12, "oidc_scopes" = $13, "token_project_id" = $14, "token_restriction_id" = $15 WHERE "federated_mapping"."id" = $16 RETURNING "id", "name", "idp_id", "domain_id", CAST("type" AS "text"), "enabled", "allowed_redirect_uris", "user_id_claim", "user_name_claim", "domain_id_claim", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "token_project_id", "token_restriction_id""#,
                    [
                        "name".into(),
                        "idp".into(),
                        "oidc".into(),
                        true.into(),
                        "url".into(),
                        "sub".into(),
                        "preferred_username".into(),
                        "domain_id".into(),
                        "groups".into(),
                        "a1,a2".into(),
                        "subject".into(),
                        json!({"department": "foo"}).into(),
                        "oidc,oauth".into(),
                        "pid".into(),
                        "trid".into(),
                        "1".into()
                    ]
                ),
            ]
        );
    }
}
