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

use crate::db::entity::federated_mapping as db_federated_mapping;
use crate::federation::backend::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn create(
    db: &DatabaseConnection,
    mapping: Mapping,
) -> Result<Mapping, FederationDatabaseError> {
    let entry = db_federated_mapping::ActiveModel {
        id: Set(mapping.id.clone()),
        domain_id: Set(mapping.domain_id.clone()),
        name: Set(mapping.name.clone()),
        idp_id: Set(mapping.idp_id.clone()),
        r#type: Set(mapping.r#type.into()),
        enabled: Set(mapping.enabled),
        allowed_redirect_uris: mapping
            .allowed_redirect_uris
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        user_id_claim: Set(mapping.user_id_claim.clone()),
        user_name_claim: Set(mapping.user_name_claim.clone()),
        domain_id_claim: mapping
            .domain_id_claim
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        groups_claim: mapping
            .groups_claim
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        bound_audiences: mapping
            .bound_audiences
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        bound_subject: mapping
            .bound_subject
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        bound_claims: mapping
            .bound_claims
            .clone()
            .map(|x| Set(Some(x)))
            .unwrap_or(NotSet),
        oidc_scopes: mapping
            .oidc_scopes
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        token_project_id: mapping
            .token_project_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        token_restriction_id: mapping
            .token_restriction_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
    };

    let db_entry: db_federated_mapping::Model = entry
        .insert(db)
        .await
        .map_err(|err| db_err(err, "persisting new federation mapping"))?;

    db_entry.try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::super::tests::get_mapping_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")]])
            .into_connection();

        let req = Mapping {
            id: "1".into(),
            name: "mapping".into(),
            domain_id: Some("foo_domain".into()),
            r#type: MappingType::default(),
            enabled: true,
            idp_id: "idp".into(),
            allowed_redirect_uris: Some(vec!["url".into()]),
            user_id_claim: "sub".into(),
            user_name_claim: "preferred_username".into(),
            domain_id_claim: Some("domain_id".into()),
            groups_claim: Some("groups".into()),
            bound_audiences: Some(vec!["a1".into(), "a2".into()]),
            bound_subject: Some("subject".into()),
            bound_claims: Some(json!({"department": "foo"})),
            //claim_mappings: Some(json!({"foo": "bar"})),
            oidc_scopes: Some(vec!["oidc".into(), "oauth".into()]),
            token_project_id: Some("pid".into()),
            token_restriction_id: Some("trid".into()),
        };

        assert_eq!(
            create(&db, req).await.unwrap(),
            get_mapping_mock("1").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "federated_mapping" ("id", "name", "idp_id", "domain_id", "type", "enabled", "allowed_redirect_uris", "user_id_claim", "user_name_claim", "domain_id_claim", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "token_project_id", "token_restriction_id") VALUES ($1, $2, $3, $4, CAST($5 AS "federated_mapping_type"), $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING "id", "name", "idp_id", "domain_id", CAST("type" AS "text"), "enabled", "allowed_redirect_uris", "user_id_claim", "user_name_claim", "domain_id_claim", "groups_claim", "bound_audiences", "bound_subject", "bound_claims", "oidc_scopes", "token_project_id", "token_restriction_id""#,
                [
                    "1".into(),
                    "mapping".into(),
                    "idp".into(),
                    "foo_domain".into(),
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
                ]
            ),]
        );
    }
}
