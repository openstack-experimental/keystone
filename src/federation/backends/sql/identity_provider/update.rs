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

use crate::config::Config;
use crate::db::entity::{
    federated_identity_provider as db_federated_identity_provider,
    prelude::FederatedIdentityProvider as DbFederatedIdentityProvider,
};
use crate::federation::backends::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn update<S: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: S,
    idp: IdentityProviderUpdate,
) -> Result<IdentityProvider, FederationDatabaseError> {
    if let Some(current) = DbFederatedIdentityProvider::find_by_id(id.as_ref())
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching current identity provider data for update"))?
    {
        let mut entry: db_federated_identity_provider::ActiveModel = current.into();
        if let Some(val) = idp.name {
            entry.name = Set(val.to_owned());
        }
        if let Some(val) = idp.enabled {
            entry.enabled = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_discovery_url {
            entry.oidc_discovery_url = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_client_id {
            entry.oidc_client_id = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_client_secret {
            entry.oidc_client_secret = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_response_mode {
            entry.oidc_response_mode = Set(val.to_owned());
        }
        if let Some(val) = idp.oidc_response_types {
            entry.oidc_response_types = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = idp.jwks_url {
            entry.jwks_url = Set(val.to_owned());
        }
        if let Some(val) = idp.jwt_validation_pubkeys {
            entry.jwt_validation_pubkeys = Set(val.clone().map(|x| x.join(",")));
        }
        if let Some(val) = idp.bound_issuer {
            entry.bound_issuer = Set(val.to_owned());
        }
        if let Some(val) = idp.provider_config {
            entry.provider_config = Set(val.to_owned());
        }
        if let Some(val) = idp.default_mapping_name {
            entry.default_mapping_name = Set(val.to_owned());
        }

        let db_entry: db_federated_identity_provider::Model = entry
            .update(db)
            .await
            .map_err(|err| db_err(err, "updating identity provider"))?;
        db_entry.try_into()
    } else {
        Err(FederationDatabaseError::IdentityProviderNotFound(
            id.as_ref().to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
    use serde_json::json;

    use crate::config::Config;

    use super::super::tests::get_idp_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")], vec![get_idp_mock("1")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let config = Config::default();

        let req = IdentityProviderUpdate {
            name: Some("idp".into()),
            enabled: Some(true),
            oidc_discovery_url: Some(Some("url".into())),
            oidc_client_id: Some(Some("oidccid".into())),
            oidc_client_secret: Some(Some("oidccs".into())),
            oidc_response_mode: Some(Some("oidcrm".into())),
            oidc_response_types: Some(Some(vec!["t1".into(), "t2".into()])),
            jwks_url: Some(Some("http://jwks".into())),
            jwt_validation_pubkeys: Some(Some(vec!["jt1".into(), "jt2".into()])),
            bound_issuer: Some(Some("bi".into())),
            default_mapping_name: Some(Some("dummy".into())),
            provider_config: Some(Some(json!({"foo": "bar"}))),
        };

        assert_eq!(
            update(&config, &db, "1", req).await.unwrap(),
            get_idp_mock("1").try_into().unwrap()
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."enabled", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider" WHERE "federated_identity_provider"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "federated_identity_provider" SET "name" = $1, "enabled" = $2, "oidc_discovery_url" = $3, "oidc_client_id" = $4, "oidc_client_secret" = $5, "oidc_response_mode" = $6, "oidc_response_types" = $7, "jwks_url" = $8, "jwt_validation_pubkeys" = $9, "bound_issuer" = $10, "default_mapping_name" = $11, "provider_config" = $12 WHERE "federated_identity_provider"."id" = $13 RETURNING "id", "name", "domain_id", "enabled", "oidc_discovery_url", "oidc_client_id", "oidc_client_secret", "oidc_response_mode", "oidc_response_types", "jwks_url", "jwt_validation_pubkeys", "bound_issuer", "default_mapping_name", "provider_config""#,
                    [
                        "idp".into(),
                        true.into(),
                        "url".into(),
                        "oidccid".into(),
                        "oidccs".into(),
                        "oidcrm".into(),
                        "t1,t2".into(),
                        "http://jwks".into(),
                        "jt1,jt2".into(),
                        "bi".into(),
                        "dummy".into(),
                        json!({"foo": "bar"}).into(),
                        "1".into(),
                    ]
                ),
            ]
        );
    }
}
