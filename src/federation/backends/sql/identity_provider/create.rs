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
use sea_orm::sea_query::OnConflict;

use crate::config::Config;
use crate::db::entity::{
    federated_identity_provider as db_federated_identity_provider,
    federation_protocol as db_old_federation_protocol,
    identity_provider as db_old_identity_provider, mapping as db_old_mapping,
};
use crate::federation::backends::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn create(
    _conf: &Config,
    db: &DatabaseConnection,
    idp: IdentityProvider,
) -> Result<IdentityProvider, FederationDatabaseError> {
    let entry = db_federated_identity_provider::ActiveModel {
        id: Set(idp.id.clone()),
        domain_id: Set(idp.domain_id.clone()),
        name: Set(idp.name.clone()),
        oidc_discovery_url: idp
            .oidc_discovery_url
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        oidc_client_id: idp.oidc_client_id.clone().map(Set).unwrap_or(NotSet).into(),
        oidc_client_secret: idp
            .oidc_client_secret
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        oidc_response_mode: idp
            .oidc_response_mode
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        oidc_response_types: idp
            .oidc_response_types
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        jwks_url: idp.jwks_url.clone().map(Set).unwrap_or(NotSet).into(),
        jwt_validation_pubkeys: idp
            .jwt_validation_pubkeys
            .clone()
            .map(|x| Set(x.join(",")))
            .unwrap_or(NotSet)
            .into(),
        bound_issuer: idp.bound_issuer.clone().map(Set).unwrap_or(NotSet).into(),
        default_mapping_name: idp
            .default_mapping_name
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        provider_config: idp
            .provider_config
            .clone()
            .map(|x| Set(Some(x)))
            .unwrap_or(NotSet),
    };

    let db_entry: db_federated_identity_provider::Model = entry
        .insert(db)
        .await
        .map_err(|err| db_err(err, "persisting new identity provider"))?;

    // For compatibility reasons add entry for the IDP old-style as well as the
    // protocol to keep constraints working
    db_old_identity_provider::ActiveModel {
        id: Set(idp.id.clone()),
        enabled: Set(true),
        description: Set(Some(idp.name.clone())),
        domain_id: Set(idp.domain_id.clone().unwrap_or("<<null>>".into())),
        authorization_ttl: NotSet,
    }
    .insert(db)
    .await
    .map_err(|err| db_err(err, "persisting v3 identity provider"))?;

    db_old_federation_protocol::ActiveModel {
        id: Set("oidc".into()),
        idp_id: Set(idp.id.clone()),
        mapping_id: Set("dummy".into()),
        remote_id_attribute: NotSet,
    }
    .insert(db)
    .await
    .map_err(|err| db_err(err, "persisting v3 federation oidc protocol"))?;

    db_old_federation_protocol::ActiveModel {
        id: Set("jwt".into()),
        idp_id: Set(idp.id.clone()),
        mapping_id: Set("dummy".into()),
        remote_id_attribute: NotSet,
    }
    .insert(db)
    .await
    .map_err(|err| db_err(err, "persisting v3 federation jwt protocol"))?;

    db_old_mapping::Entity::insert(db_old_mapping::ActiveModel {
        id: Set("dummy".into()),
        rules: Set(Some("\"[]\"".into())),
        schema_version: Set("1.0".into()),
    })
    .on_conflict(
        OnConflict::column(db_old_mapping::Column::Id)
            // Special handling for
            // [mysql](https://docs.rs/sea-query/0.32.7/sea_query/query/struct.OnConflict.html#method.do_nothing_on)
            .do_nothing_on([db_old_mapping::Column::Id])
            .to_owned(),
    )
    .on_empty_do_nothing()
    .exec(db)
    .await
    .map_err(|err| db_err(err, "persisting v3 federation mapping"))?;

    db_entry.try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
    use serde_json::json;

    use crate::config::Config;

    use super::super::tests::{get_idp_mock, get_old_idp_mock, get_old_proto_mock};
    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .append_query_results([vec![get_old_idp_mock("1")]])
            .append_query_results([vec![get_old_proto_mock("1")]])
            .append_query_results([vec![get_old_proto_mock("2")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let config = Config::default();

        let req = IdentityProvider {
            id: "1".into(),
            name: "idp".into(),
            domain_id: Some("foo_domain".into()),
            oidc_discovery_url: Some("url".into()),
            oidc_client_id: Some("oidccid".into()),
            oidc_client_secret: Some("oidccs".into()),
            oidc_response_mode: Some("oidcrm".into()),
            oidc_response_types: Some(vec!["t1".into(), "t2".into()]),
            jwks_url: Some("http://jwks".into()),
            jwt_validation_pubkeys: Some(vec!["jt1".into(), "jt2".into()]),
            bound_issuer: Some("bi".into()),
            default_mapping_name: Some("dummy".into()),
            provider_config: Some(json!({"foo": "bar"})),
        };

        assert_eq!(
            create(&config, &db, req).await.unwrap(),
            get_idp_mock("1").try_into().unwrap()
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "federated_identity_provider" ("id", "name", "domain_id", "oidc_discovery_url", "oidc_client_id", "oidc_client_secret", "oidc_response_mode", "oidc_response_types", "jwks_url", "jwt_validation_pubkeys", "bound_issuer", "default_mapping_name", "provider_config") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING "id", "name", "domain_id", "oidc_discovery_url", "oidc_client_id", "oidc_client_secret", "oidc_response_mode", "oidc_response_types", "jwks_url", "jwt_validation_pubkeys", "bound_issuer", "default_mapping_name", "provider_config""#,
                    [
                        "1".into(),
                        "idp".into(),
                        "foo_domain".into(),
                        "url".into(),
                        "oidccid".into(),
                        "oidccs".into(),
                        "oidcrm".into(),
                        "t1,t2".into(),
                        "http://jwks".into(),
                        "jt1,jt2".into(),
                        "bi".into(),
                        "dummy".into(),
                        json!({"foo": "bar"}).into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "identity_provider" ("id", "enabled", "description", "domain_id") VALUES ($1, $2, $3, $4) RETURNING "id", "enabled", "description", "domain_id", "authorization_ttl""#,
                    ["1".into(), true.into(), "idp".into(), "foo_domain".into(),]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "federation_protocol" ("id", "idp_id", "mapping_id") VALUES ($1, $2, $3) RETURNING "id", "idp_id", "mapping_id", "remote_id_attribute""#,
                    ["oidc".into(), "1".into(), "dummy".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "federation_protocol" ("id", "idp_id", "mapping_id") VALUES ($1, $2, $3) RETURNING "id", "idp_id", "mapping_id", "remote_id_attribute""#,
                    ["jwt".into(), "1".into(), "dummy".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "mapping" ("id", "rules", "schema_version") VALUES ($1, $2, $3) ON CONFLICT ("id") DO NOTHING RETURNING "id""#,
                    ["dummy".into(), "\"[]\"".into(), "1.0".into()]
                ),
            ]
        );
    }
}
