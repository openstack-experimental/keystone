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
//! # Create application credential
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::application_credential::backend::error::{ApplicationCredentialDatabaseError, db_err};
use crate::application_credential::types::*;
use crate::common::password_hashing;
use crate::config::Config;
use crate::db::entity::{
    access_rule as db_access_rule, application_credential as db_application_credential,
    application_credential_access_rule as db_application_credential_access_rule,
    application_credential_role as db_application_credential_role,
    prelude::{
        AccessRule as DbAccessRule, ApplicationCredentialRole as DbApplicationCredentialRole,
    },
};

impl TryFrom<ApplicationCredentialCreate> for db_application_credential::ActiveModel {
    type Error = ApplicationCredentialDatabaseError;
    fn try_from(value: ApplicationCredentialCreate) -> Result<Self, Self::Error> {
        Ok(Self {
            internal_id: NotSet,
            id: Set(value.id.unwrap_or(Uuid::new_v4().simple().to_string())),
            name: Set(value.name),
            secret_hash: NotSet,
            description: value.description.map(Set).unwrap_or(NotSet).into(),
            user_id: Set(value.user_id),
            project_id: Set(Some(value.project_id)),
            expires_at: value
                .expires_at
                .map(|val| Set(Some(val.timestamp_micros())))
                .unwrap_or(NotSet),
            system: NotSet,
            unrestricted: Set(Some(value.unrestricted.unwrap_or_default())),
        })
    }
}

/// Create the application credential.
pub async fn create(
    conf: &Config,
    db: &DatabaseConnection,
    rec: ApplicationCredentialCreate,
) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialDatabaseError> {
    // Do a lot of stuff in a transaction
    let txn = db.begin().await.map_err(|err| {
        db_err(
            err,
            "starting transaction for persisting application credential",
        )
    })?;
    let mut model = db_application_credential::ActiveModel::try_from(rec.clone())?;
    model.secret_hash = if let Some(secret) = &rec.secret {
        Set(password_hashing::hash_password(conf, secret.expose_secret()).await?)
    } else {
        return Err(ApplicationCredentialDatabaseError::SecretMissing);
    };

    // Insert main entry
    let db_entry = model
        .insert(&txn)
        .await
        .map_err(|err| db_err(err, "persisting application credential"))?;

    // Insert app cred role relations
    if !rec.roles.is_empty() {
        DbApplicationCredentialRole::insert_many(rec.roles.clone().into_iter().map(|role| {
            db_application_credential_role::ActiveModel {
                application_credential_id: Set(db_entry.internal_id),
                role_id: Set(role.id),
            }
        }))
        .exec(&txn)
        .await
        .map_err(|err| db_err(err, "persisting application credential role relations"))?;
    }

    let internal_id = db_entry.internal_id;

    let mut builder: ApplicationCredentialCreateResponseBuilder = db_entry.try_into()?;
    builder.roles(rec.roles.clone());
    if let Some(secret) = rec.secret {
        builder.secret(secret);
    }
    // Process access rules
    if let Some(access_rules) = rec.access_rules {
        builder.access_rules(
            process_access_rules(&txn, access_rules.into_iter(), internal_id, rec.user_id)
                .await?
                .into_iter()
                .collect::<Vec<_>>(),
        );
    }
    txn.commit().await.map_err(|err| {
        db_err(
            err,
            "committing transaction for persisting application credential",
        )
    })?;
    Ok(builder.build()?)
}

/// Process access rules.
///
/// - Check whether access rule with the same ID (`external_id`) or the same
///   parameters (`path`, `method`, `service`, `user_id`) exists.
/// - When multiple records are matching raise an error.
/// - When only 1 record exist - reuse it (id).
/// - When not exist - create new one.
async fn process_access_rules<C, I, S>(
    db: &C,
    rules: I,
    application_credential_internal_id: i32,
    user_id: S,
) -> Result<Vec<AccessRule>, ApplicationCredentialDatabaseError>
where
    C: ConnectionTrait,
    I: IntoIterator<Item = AccessRuleCreate>,
    S: AsRef<str>,
{
    let mut results: Vec<AccessRule> = Vec::new();
    for rule in rules {
        let existing_rules = DbAccessRule::find()
            .filter(
                Condition::any()
                    .add_option(
                        rule.id
                            .clone()
                            .map(|rule_id| db_access_rule::Column::ExternalId.eq(rule_id)),
                    )
                    .add(
                        Condition::all()
                            .add(db_access_rule::Column::Path.eq(rule.path.clone()))
                            .add(db_access_rule::Column::Method.eq(rule.method.clone()))
                            .add(db_access_rule::Column::Service.eq(rule.service.clone()))
                            .add(db_access_rule::Column::UserId.eq(user_id.as_ref())),
                    ),
            )
            .all(db)
            .await
            .map_err(|err| db_err(err, "searching matching access rules"))?;
        let existing_rule = if existing_rules.is_empty() {
            Some(
                db_access_rule::ActiveModel {
                    id: NotSet,
                    method: Set(rule.method.clone()),
                    path: Set(rule.path.clone()),
                    service: Set(rule.service.clone()),
                    external_id: Set(Some(
                        rule.id
                            .clone()
                            .unwrap_or(uuid::Uuid::new_v4().simple().to_string()),
                    )),
                    user_id: Set(Some(user_id.as_ref().to_string())),
                }
                .insert(db)
                .await
                .map_err(|err| db_err(err, "persising access rule"))?,
            )
        } else if existing_rules.len() == 1 {
            existing_rules.first().cloned()
        } else {
            return Err(ApplicationCredentialDatabaseError::AccessRuleConflict);
        };
        if let Some(rule) = existing_rule {
            db_application_credential_access_rule::ActiveModel {
                application_credential_id: Set(application_credential_internal_id),
                access_rule_id: Set(rule.id),
            }
            .insert(db)
            .await
            .map_err(|err| db_err(err, "persising access rule relation"))?;
            results.push(rule.try_into()?);
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use chrono::{Timelike, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};

    use super::super::tests::*;
    use super::*;
    use crate::assignment::types::Role;
    use crate::config::PasswordHashingAlgo;

    #[tokio::test]
    async fn test_create() {
        let expire = Utc::now()
            .with_nanosecond(0)
            .expect("0 nanoseconds")
            .to_utc();
        let mut config = Config::default();
        config.identity.password_hashing_algorithm = PasswordHashingAlgo::None;

        let uuid1 = uuid::Uuid::new_v4().simple().to_string();
        let uuid2 = uuid::Uuid::new_v4().simple().to_string();
        let sot = ApplicationCredentialCreate {
            access_rules: Some(vec![
                AccessRuleCreate {
                    id: Some(uuid1.clone()),
                    method: Some("get".into()),
                    path: Some("/path1".into()),
                    service: Some("service".into()),
                },
                AccessRuleCreate {
                    id: Some(uuid2.clone()),
                    method: Some("get".into()),
                    path: Some("/path2".into()),
                    service: Some("service".into()),
                },
            ]),
            description: Some("description".into()),
            expires_at: Some(expire),
            id: Some("app_cred_id".into()),
            name: "app_cred_name".into(),
            project_id: "project_id".into(),
            roles: vec![
                Role {
                    id: "role_a".into(),
                    ..Default::default()
                },
                Role {
                    id: "role_b".into(),
                    ..Default::default()
                },
            ],
            secret: Some("secret".into()),
            unrestricted: Some(true),
            user_id: "user_id".into(),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_application_credential_mock_from_active(
                db_application_credential::ActiveModel::try_from(sot.clone()).unwrap(),
                1,
            )]])
            .append_exec_results([MockExecResult {
                rows_affected: 2,
                ..Default::default()
            }])
            .append_query_results([Vec::<db_access_rule::Model>::new()])
            .append_query_results([vec![get_access_rule_mock("app_cred_rule_id1", Some(1))]])
            .append_query_results([vec![db_application_credential_access_rule::Model {
                application_credential_id: 1,
                access_rule_id: 1,
            }]])
            .append_query_results([Vec::<db_access_rule::Model>::new()])
            .append_query_results([vec![get_access_rule_mock("app_cred_rule_id2", Some(2))]])
            .append_query_results([vec![db_application_credential_access_rule::Model {
                application_credential_id: 1,
                access_rule_id: 2,
            }]])
            .into_connection();

        let ac = create(&config, &db, sot).await.unwrap();
        assert_eq!(ac.id, "app_cred_id".to_string());
        assert_eq!(ac.name, "app_cred_name".to_string());
        assert_eq!(ac.description, Some("description".to_string()));
        assert_eq!(ac.user_id, "user_id".to_string());
        assert_eq!(ac.project_id, "project_id".to_string());
        assert_eq!(ac.expires_at, Some(expire));
        assert!(ac.unrestricted);
        let role_ids: Vec<String> = ac.roles.iter().map(|role| role.id.clone()).collect();
        assert!(role_ids.contains(&"role_a".to_string()));
        assert!(role_ids.contains(&"role_b".to_string()));

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#,),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "application_credential" ("id", "name", "secret_hash", "description", "user_id", "project_id", "expires_at", "unrestricted") VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING "internal_id", "id", "name", "secret_hash", "description", "user_id", "project_id", "expires_at", "system", "unrestricted""#,
                    [
                        "app_cred_id".into(),
                        "app_cred_name".into(),
                        "secret".into(),
                        "description".into(),
                        "user_id".into(),
                        "project_id".into(),
                        expire.to_utc().timestamp_micros().into(),
                        true.into()
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "application_credential_role" ("application_credential_id", "role_id") VALUES ($1, $2), ($3, $4) RETURNING "application_credential_id", "role_id""#,
                    [1.into(), "role_a".into(), 1.into(), "role_b".into(),]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "access_rule"."id", "access_rule"."service", "access_rule"."path", "access_rule"."method", "access_rule"."external_id", "access_rule"."user_id" FROM "access_rule" WHERE "access_rule"."external_id" = $1 OR ("access_rule"."path" = $2 AND "access_rule"."method" = $3 AND "access_rule"."service" = $4 AND "access_rule"."user_id" = $5)"#,
                    [
                        uuid1.clone().into(),
                        "/path1".into(),
                        "get".into(),
                        "service".into(),
                        "user_id".into(),
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "access_rule" ("service", "path", "method", "external_id", "user_id") VALUES ($1, $2, $3, $4, $5) RETURNING "id", "service", "path", "method", "external_id", "user_id""#,
                    [
                        "service".into(),
                        "/path1".into(),
                        "get".into(),
                        uuid1.into(),
                        "user_id".into()
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "application_credential_access_rule" ("application_credential_id", "access_rule_id") VALUES ($1, $2) RETURNING "application_credential_id", "access_rule_id""#,
                    [1.into(), 1.into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "access_rule"."id", "access_rule"."service", "access_rule"."path", "access_rule"."method", "access_rule"."external_id", "access_rule"."user_id" FROM "access_rule" WHERE "access_rule"."external_id" = $1 OR ("access_rule"."path" = $2 AND "access_rule"."method" = $3 AND "access_rule"."service" = $4 AND "access_rule"."user_id" = $5)"#,
                    [
                        uuid2.clone().into(),
                        "/path2".into(),
                        "get".into(),
                        "service".into(),
                        "user_id".into(),
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "access_rule" ("service", "path", "method", "external_id", "user_id") VALUES ($1, $2, $3, $4, $5) RETURNING "id", "service", "path", "method", "external_id", "user_id""#,
                    [
                        "service".into(),
                        "/path2".into(),
                        "get".into(),
                        uuid2.into(),
                        "user_id".into()
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "application_credential_access_rule" ("application_credential_id", "access_rule_id") VALUES ($1, $2) RETURNING "application_credential_id", "access_rule_id""#,
                    [1.into(), 2.into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#,)
            ])]
        );
    }
}
