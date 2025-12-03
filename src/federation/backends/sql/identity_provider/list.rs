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

use crate::config::Config;
use crate::db::entity::{
    federated_identity_provider as db_federated_identity_provider,
    prelude::FederatedIdentityProvider as DbFederatedIdentityProvider,
};
use crate::federation::backends::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn list(
    _conf: &Config,
    db: &DatabaseConnection,
    params: &IdentityProviderListParameters,
) -> Result<Vec<IdentityProvider>, FederationDatabaseError> {
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

    let db_entities: Vec<db_federated_identity_provider::Model> = select
        .all(db)
        .await
        .map_err(|err| db_err(err, "listing identity providers"))?;
    let results: Result<Vec<IdentityProvider>, _> = db_entities
        .into_iter()
        .map(TryInto::<IdentityProvider>::try_into)
        .collect();

    results
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use std::collections::HashSet;

    use crate::config::Config;

    use super::super::tests::get_idp_mock;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();
        let config = Config::default();
        assert!(
            list(&config, &db, &IdentityProviderListParameters::default())
                .await
                .is_ok()
        );
        assert_eq!(
            list(
                &config,
                &db,
                &IdentityProviderListParameters {
                    name: Some("idp_name".into()),
                    domain_ids: Some(HashSet::from([Some("did".into())])),
                }
            )
            .await
            .unwrap(),
            vec![IdentityProvider {
                id: "1".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                ..Default::default()
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."enabled", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."enabled", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider" WHERE "federated_identity_provider"."name" = $1 AND "federated_identity_provider"."domain_id" IN ($2)"#,
                    ["idp_name".into(), "did".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_with_null_domain_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();
        let config = Config::default();
        list(
            &config,
            &db,
            &IdentityProviderListParameters {
                name: Some("idp_name".into()),
                domain_ids: Some(HashSet::from([None, Some("did".into())])),
            },
        )
        .await
        .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."enabled", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider" WHERE "federated_identity_provider"."name" = $1 AND ("federated_identity_provider"."domain_id" IN ($2) OR "federated_identity_provider"."domain_id" IS NULL)"#,
                ["idp_name".into(), "did".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list_without_domain_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();
        let config = Config::default();
        list(
            &config,
            &db,
            &IdentityProviderListParameters {
                name: Some("idp_name".into()),
                domain_ids: None,
            },
        )
        .await
        .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."enabled", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider" WHERE "federated_identity_provider"."name" = $1"#,
                ["idp_name".into()]
            ),]
        );
    }
}
