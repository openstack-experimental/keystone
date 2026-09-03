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
//! # Verify application credential
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use secrecy::SecretString;

use openstack_keystone_config::Config;
use openstack_keystone_core::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_password_hashing as password_hashing;

use crate::entity::{
    application_credential as db_application_credential,
    prelude::ApplicationCredential as DbApplicationCredential,
};

pub async fn verify_secret(
    config: &Config,
    db: &DatabaseConnection,
    credential_id: &str,
    secret: &SecretString,
) -> Result<(), ApplicationCredentialProviderError> {
    let record = DbApplicationCredential::find()
        .filter(db_application_credential::Column::Id.eq(credential_id))
        .one(db)
        .await
        .context("looking up application credential for authentication")?
        .ok_or(ApplicationCredentialProviderError::AuthenticationFailed)?;

    // record is db_application_credential::Model, which has secret_hash
    let matched = password_hashing::verify_password(config, secret, &record.secret_hash)
        .await
        .map_err(ApplicationCredentialProviderError::password_hash)?;

    if !matched {
        return Err(ApplicationCredentialProviderError::AuthenticationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use openstack_keystone_config::PasswordHashingAlgo;

    use super::*;
    use crate::entity::application_credential as db_application_credential;

    fn make_app_cred_model(id: &str, secret_hash: &str) -> db_application_credential::Model {
        db_application_credential::Model {
            internal_id: 1,
            id: id.to_string(),
            name: "fake appcred".to_string(),
            secret_hash: secret_hash.to_string(),
            description: Some("description".to_string()),
            user_id: "user_id".to_string(),
            project_id: Some("project_id".to_string()),
            expires_at: Some(DateTime::<Utc>::MIN_UTC.timestamp_micros()),
            system: None,
            unrestricted: Some(true),
        }
    }

    #[tokio::test]
    async fn test_verify_secret_success() {
        let mut config = Config::default();
        config.identity.password_hashing_algorithm = PasswordHashingAlgo::None;

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![make_app_cred_model("app_cred_id", "test_secret")]])
            .into_connection();

        let result = verify_secret(&config, &db, "app_cred_id", &"test_secret".into()).await;

        assert!(result.is_ok());

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "application_credential"."internal_id", "application_credential"."id", "application_credential"."name", "application_credential"."secret_hash", "application_credential"."description", "application_credential"."user_id", "application_credential"."project_id", "application_credential"."expires_at", "application_credential"."system", "application_credential"."unrestricted" FROM "application_credential" WHERE "application_credential"."id" = $1 LIMIT $2"#,
                ["app_cred_id".into(), 1u64.into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_verify_secret_wrong_secret() {
        let mut config = Config::default();
        config.identity.password_hashing_algorithm = PasswordHashingAlgo::None;

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![make_app_cred_model("app_cred_id", "test_secret")]])
            .into_connection();

        let result = verify_secret(&config, &db, "app_cred_id", &"wrong_secret".into()).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ApplicationCredentialProviderError::AuthenticationFailed
        ));
    }

    #[tokio::test]
    async fn test_verify_secret_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_application_credential::Model>::new()])
            .into_connection();

        let mut config = Config::default();
        config.identity.password_hashing_algorithm = PasswordHashingAlgo::None;

        let result = verify_secret(&config, &db, "nonexistent_id", &"test_secret".into()).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ApplicationCredentialProviderError::AuthenticationFailed
        ));
    }
}
