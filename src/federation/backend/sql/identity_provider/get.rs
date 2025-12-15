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
    federated_identity_provider as db_federated_identity_provider,
    prelude::FederatedIdentityProvider as DbFederatedIdentityProvider,
};
use crate::federation::backend::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<IdentityProvider>, FederationDatabaseError> {
    let select = DbFederatedIdentityProvider::find_by_id(id.as_ref());

    let entry: Option<db_federated_identity_provider::Model> = select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching identity provider by id"))?;
    entry.map(TryInto::try_into).transpose()
}
#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_idp_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();

        assert_eq!(
            get(&db, "1").await.unwrap().unwrap(),
            IdentityProvider {
                id: "1".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                ..Default::default()
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_identity_provider"."id", "federated_identity_provider"."name", "federated_identity_provider"."domain_id", "federated_identity_provider"."enabled", "federated_identity_provider"."oidc_discovery_url", "federated_identity_provider"."oidc_client_id", "federated_identity_provider"."oidc_client_secret", "federated_identity_provider"."oidc_response_mode", "federated_identity_provider"."oidc_response_types", "federated_identity_provider"."jwks_url", "federated_identity_provider"."jwt_validation_pubkeys", "federated_identity_provider"."bound_issuer", "federated_identity_provider"."default_mapping_name", "federated_identity_provider"."provider_config" FROM "federated_identity_provider" WHERE "federated_identity_provider"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }
}
