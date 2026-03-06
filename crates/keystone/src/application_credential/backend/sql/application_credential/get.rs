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

use crate::application_credential::{
    ApplicationCredentialProviderError,
    types::{AccessRule, ApplicationCredential, ApplicationCredentialBuilder},
};
use crate::db::entity::{
    application_credential as db_application_credential,
    prelude::{
        AccessRule as DbAccessRule, ApplicationCredential as DbApplicationCredential,
        ApplicationCredentialRole as DbApplicationCredentialRole,
    },
};
use crate::error::DbContextExt;
use crate::role::types::RoleRef;

/// Get application credential by the ID.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError> {
    let select = DbApplicationCredential::find()
        .filter(db_application_credential::Column::Id.eq(id.as_ref()));

    if let Some(ref entry) = select
        .one(db)
        .await
        .context("fetching application credential by id")?
    {
        let mut builder: ApplicationCredentialBuilder = entry.try_into()?;
        // Query roles and rules in parallel
        let (roles_handle, rules_handle) = tokio::join!(
            entry.find_related(DbApplicationCredentialRole).all(db),
            entry.find_related(DbAccessRule).all(db)
        );

        let roles: Vec<RoleRef> = roles_handle
            .context("fetching application credential roles")?
            .into_iter()
            .map(Into::into)
            .collect();
        let rules = rules_handle
            .context("fetching application credential rules")?
            .into_iter()
            .map(TryInto::<AccessRule>::try_into)
            .collect::<Result<Vec<AccessRule>, _>>()?;
        builder.roles(roles);
        builder.access_rules(rules);
        return Ok(Some(builder.build()?));
    };
    Ok(None)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_application_credential_mock(
                "app_cred_id",
                Some(12345),
            )]])
            .append_query_results([vec![get_application_credential_role_mock(12345, "role_id")]])
            .append_query_results([vec![get_access_rule_mock("app_cred_rule_id", None)]])
            .into_connection();

        assert_eq!(
            get(&db, "app_cred_id").await.unwrap().unwrap(),
            ApplicationCredential {
                id: "app_cred_id".into(),
                name: "fake appcred".into(),
                description: Some("description".into()),
                user_id: "user_id".into(),
                project_id: "project_id".into(),
                expires_at: Some(DateTime::<Utc>::MIN_UTC.to_utc()),
                unrestricted: true,
                roles: vec![RoleRef {
                    id: "role_id".into(),
                    domain_id: None,
                    name: None,
                }],
                access_rules: Some(vec![AccessRule {
                    id: "app_cred_rule_id".into(),
                    path: Some("/path".into()),
                    method: Some("method".into()),
                    service: Some("service".into())
                }])
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "application_credential"."internal_id", "application_credential"."id", "application_credential"."name", "application_credential"."secret_hash", "application_credential"."description", "application_credential"."user_id", "application_credential"."project_id", "application_credential"."expires_at", "application_credential"."system", "application_credential"."unrestricted" FROM "application_credential" WHERE "application_credential"."id" = $1 LIMIT $2"#,
                    ["app_cred_id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "application_credential_role"."application_credential_id", "application_credential_role"."role_id" FROM "application_credential_role" INNER JOIN "application_credential" ON "application_credential"."internal_id" = "application_credential_role"."application_credential_id" WHERE "application_credential"."internal_id" = $1"#,
                    [12345.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "access_rule"."id", "access_rule"."service", "access_rule"."path", "access_rule"."method", "access_rule"."external_id", "access_rule"."user_id" FROM "access_rule" INNER JOIN "application_credential_access_rule" ON "application_credential_access_rule"."access_rule_id" = "access_rule"."id" INNER JOIN "application_credential" ON "application_credential"."internal_id" = "application_credential_access_rule"."application_credential_id" WHERE "application_credential"."internal_id" = $1"#,
                    [12345.into()]
                ),
            ]
        );
    }
}
