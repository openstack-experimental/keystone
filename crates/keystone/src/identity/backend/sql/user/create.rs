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

use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::{ConnectionTrait, TransactionTrait};

use crate::common::password_hashing;
use crate::config::Config;
use crate::db::entity::{
    federated_user as db_federated_user, password as db_password, user as db_user,
};
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;
use crate::identity::types::*;

use super::super::federated_user;
use super::super::local_user;
use super::super::password;
use super::super::user_option;

#[tracing::instrument(skip_all)]
pub async fn create_main<C>(
    conf: &Config,
    db: &C,
    user: &UserCreate,
    created_at: Option<DateTime<Utc>>,
) -> Result<db_user::Model, IdentityDatabaseError>
where
    C: ConnectionTrait,
{
    Ok(user
        .to_user_active_model(conf, created_at)?
        .insert(db)
        .await
        .context("inserting user entry")?)
}

#[tracing::instrument(skip(conf, db))]
pub async fn create(
    conf: &Config,
    db: &DatabaseConnection,
    user: UserCreate,
) -> Result<UserResponse, IdentityDatabaseError> {
    // Do a lot of stuff in a transaction

    let txn = db
        .begin()
        .await
        .context("starting transaction for persisting user")?;

    let now = Utc::now();
    let main_user = create_main(conf, &txn, &user, Some(now)).await?;
    if let Some(opts) = &user.options {
        // Persist user options when passed
        user_option::create(&txn, main_user.id.clone(), opts).await?;
    }

    let mut response_builder = UserResponseBuilder::default();
    response_builder.merge_user_data(
        &main_user,
        user.options.as_ref().unwrap_or(&UserOptions::default()),
        None,
    );

    if let Some(federation_data) = &user.federated {
        let mut federated_entities: Vec<db_federated_user::Model> = Vec::new();
        for federated_user in federation_data {
            if federated_user.protocols.is_empty() {
                federated_entities.push(
                    federated_user::create(
                        &txn,
                        db_federated_user::ActiveModel {
                            id: NotSet,
                            user_id: Set(main_user.id.clone()),
                            idp_id: Set(federated_user.idp_id.clone()),
                            protocol_id: Set("oidc".into()),
                            unique_id: Set(federated_user.unique_id.clone()),
                            display_name: Set(Some(user.name.clone())),
                        },
                    )
                    .await?,
                );
            } else {
                for proto in &federated_user.protocols {
                    //for proto in &federated_user.protocol_ids {
                    federated_entities.push(
                        federated_user::create(
                            &txn,
                            db_federated_user::ActiveModel {
                                id: NotSet,
                                user_id: Set(main_user.id.clone()),
                                idp_id: Set(federated_user.idp_id.clone()),
                                protocol_id: Set(proto.protocol_id.clone()),
                                unique_id: Set(federated_user.unique_id.clone()),
                                display_name: Set(Some(user.name.clone())),
                            },
                        )
                        .await?,
                    );
                }
            }
        }
        response_builder.merge_federated_user_data(federated_entities);
    } else {
        // When the user is not a federated one we can only assume it is a local user.
        // For creating nonlocal user or service account dedicated API should be
        // used.
        let local_user = local_user::create(conf, &txn, &main_user, &user).await?;
        response_builder.merge_local_user_data(&local_user);

        if let Some(password) = &user.password {
            let mut passwords: Vec<db_password::Model> = Vec::new();
            let password_entry = password::create(
                &txn,
                local_user.id,
                password_hashing::hash_password(conf, password).await?,
                None,
            )
            .await?;

            passwords.push(password_entry);
            response_builder.merge_passwords_data(passwords);
        }
    }

    txn.commit()
        .await
        .context("committing the user creation transaction")?;

    Ok(response_builder.build()?)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;
    use crate::config::Config;
    use crate::identity::backend::sql::{
        federated_user::tests::get_federated_user_mock, local_user::tests::get_local_user_mock,
        password::tests::get_password_mock, user::tests::get_user_mock,
    };

    #[tokio::test]
    async fn test_create_main() {
        let sot_db_res = db_user::Model {
            id: "1".into(),
            domain_id: "did".into(),
            enabled: Some(true),
            ..Default::default()
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![sot_db_res.clone()]])
            .into_connection();

        let now = Utc::now();
        let req = UserCreateBuilder::default()
            .default_project_id("dpid")
            .domain_id("did")
            .id("1")
            .name("foo")
            .enabled(true)
            .build()
            .unwrap();
        assert_eq!(
            create_main(&Config::default(), &db, &req, Some(now))
                .await
                .unwrap(),
            sot_db_res
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "user" ("created_at", "default_project_id", "domain_id", "enabled", "extra", "id") VALUES ($1, $2, $3, $4, $5, $6) RETURNING "created_at", "default_project_id", "domain_id", "enabled", "extra", "id", "last_active_at""#,
                [
                    now.naive_utc().into(),
                    "dpid".into(),
                    "did".into(),
                    true.into(),
                    "{}".into(),
                    "1".into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_create_main_disable_inactivity_tracking() {
        let sot_db_res = db_user::Model {
            id: "1".into(),
            domain_id: "did".into(),
            enabled: Some(true),
            ..Default::default()
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![sot_db_res.clone()]])
            .into_connection();

        let now = Utc::now();
        let req = UserCreateBuilder::default()
            .default_project_id("dpid")
            .domain_id("did")
            .id("1")
            .name("foo")
            .enabled(true)
            .build()
            .unwrap();
        let mut cfg = Config::default();
        cfg.security_compliance.disable_user_account_days_inactive = Some(1);
        assert_eq!(
            create_main(&cfg, &db, &req, Some(now)).await.unwrap(),
            sot_db_res
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "user" ("created_at", "default_project_id", "domain_id", "enabled", "extra", "id", "last_active_at") VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING "created_at", "default_project_id", "domain_id", "enabled", "extra", "id", "last_active_at""#,
                [
                    now.naive_utc().into(),
                    "dpid".into(),
                    "did".into(),
                    true.into(),
                    "{}".into(),
                    "1".into(),
                    now.naive_utc().date().into(),
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_create_federated() {
        let user_opts = UserOptions {
            ignore_password_expiry: Some(true),
            ..Default::default()
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_mock("1")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_query_results([vec![get_federated_user_mock("1")]])
            .into_connection();
        let mut federation_data = FederationBuilder::default();
        federation_data
            .idp_id("idp_id")
            .unique_id("unique_id")
            .protocols(vec![FederationProtocol {
                protocol_id: "oidc".into(),
                unique_id: "unique_id".into(),
            }]);
        let req = UserCreateBuilder::default()
            .default_project_id("dpid")
            .domain_id("did")
            .id("1")
            .name("foo")
            .enabled(true)
            .federated(vec![federation_data.build().unwrap()])
            .options(user_opts.clone())
            .build()
            .unwrap();
        let sot = create(&Config::default(), &db, req).await.unwrap();
        assert_eq!(sot.name, "foo");
        assert_eq!(sot.options, user_opts);
    }

    #[tokio::test]
    async fn test_create_local() {
        let user_opts = UserOptions {
            ignore_password_expiry: Some(true),
            ..Default::default()
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_mock("1")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_query_results([vec![get_local_user_mock("1")]])
            .append_query_results([vec![get_password_mock(1)]])
            .into_connection();
        let req = UserCreateBuilder::default()
            .default_project_id("dpid")
            .domain_id("did")
            .id("1")
            .name("foo")
            .enabled(true)
            .password("foobar")
            .options(user_opts.clone())
            .build()
            .unwrap();
        let sot = create(&Config::default(), &db, req).await.unwrap();
        assert_eq!(sot.name, "foo_domain");
        assert_eq!(sot.options, user_opts);
    }
}
