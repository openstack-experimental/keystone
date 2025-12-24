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
use sea_orm::{Cursor, SelectModel};

use crate::application_credential::backend::error::ApplicationCredentialDatabaseError;
use crate::application_credential::types::*;
use crate::assignment::types::Role;
use crate::db::entity::{
    application_credential as db_application_credential,
    prelude::{
        AccessRule as DbAccessRule, ApplicationCredential as DbApplicationCredential,
        ApplicationCredentialAccessRule as DbApplicationCredentialRule,
        ApplicationCredentialRole as DbApplicationCredentialRole, Role as DbRole,
    },
};
use crate::error::DbContextExt;

/// Prepare the paginated query for listing application credentials.
fn get_list_query(
    params: &ApplicationCredentialListParameters,
) -> Result<Cursor<SelectModel<db_application_credential::Model>>, ApplicationCredentialDatabaseError>
{
    let mut select = DbApplicationCredential::find()
        .filter(db_application_credential::Column::UserId.eq(&params.user_id));

    if let Some(val) = &params.name {
        select = select.filter(db_application_credential::Column::Name.eq(val));
    }

    let mut cursor = select.cursor_by(db_application_credential::Column::Id);
    if let Some(limit) = params.limit {
        cursor.first(limit);
    }
    if let Some(marker) = &params.marker {
        cursor.after(marker);
    }
    Ok(cursor)
}

/// List application credentials.
pub async fn list(
    db: &DatabaseConnection,
    params: &ApplicationCredentialListParameters,
) -> Result<Vec<ApplicationCredential>, ApplicationCredentialDatabaseError> {
    let db_entities: Vec<db_application_credential::Model> = get_list_query(params)?
        .all(db)
        .await
        .context("listing application credentials")?;

    let (roles_handle, rules_handle) = tokio::join!(
        db_entities.load_many_to_many(DbRole, DbApplicationCredentialRole, db),
        db_entities.load_many_to_many(DbAccessRule, DbApplicationCredentialRule, db)
    );
    let roles = roles_handle
        .context("fetching roles for application credential list")?
        .into_iter()
        .map(|apr| {
            apr.into_iter()
                .map(TryInto::<Role>::try_into)
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<Vec<_>>, _>>()?;
    let rules = rules_handle
        .context("fetching access rules for application credential list")?
        .into_iter()
        .map(|apc| {
            apc.into_iter()
                .map(TryInto::<AccessRule>::try_into)
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<Vec<_>>, _>>()?;
    let mut results: Vec<ApplicationCredential> = Vec::new();
    for (ref apc, (roles, rules)) in db_entities
        .into_iter()
        .zip(roles.into_iter().zip(rules.into_iter()))
    {
        let mut builder: ApplicationCredentialBuilder = apc.try_into()?;
        builder.roles(roles);
        builder.access_rules(rules);
        results.push(builder.build()?);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::*;
    use super::*;

    use crate::assignment::backend::sql::role::tests::get_role_mock;
    use crate::db::entity::{
        application_credential_access_rule as db_application_credential_access_rule,
        application_credential_role as db_application_credential_role,
    };

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_application_credential_mock("app_cred_id1", Some(1)),
                get_application_credential_mock("app_cred_id2", Some(2)),
            ]])
            .append_query_results([vec![
                db_application_credential_role::Model {
                    application_credential_id: 1,
                    role_id: "role_id1".into(),
                },
                db_application_credential_role::Model {
                    application_credential_id: 1,
                    role_id: "role_id".into(),
                },
                db_application_credential_role::Model {
                    application_credential_id: 2,
                    role_id: "role_id2".into(),
                },
            ]])
            .append_query_results([vec![get_role_mock("role_id1"), get_role_mock("role_id2")]])
            .append_query_results([vec![
                db_application_credential_access_rule::Model {
                    application_credential_id: 1,
                    access_rule_id: 1,
                },
                db_application_credential_access_rule::Model {
                    application_credential_id: 1,
                    access_rule_id: 2,
                },
            ]])
            .append_query_results([vec![
                get_access_rule_mock("app_cred_rule1", Some(1)),
                get_access_rule_mock("app_cred_rule2", Some(2)),
            ]])
            .into_connection();
        assert!(
            list(
                &db,
                &ApplicationCredentialListParameters {
                    user_id: "user_id".into(),
                    ..Default::default()
                },
            )
            .await
            .is_ok()
        );

        for (l,r) in db.into_transaction_log().iter().zip([
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "application_credential"."internal_id", "application_credential"."id", "application_credential"."name", "application_credential"."secret_hash", "application_credential"."description", "application_credential"."user_id", "application_credential"."project_id", "application_credential"."expires_at", "application_credential"."system", "application_credential"."unrestricted" FROM "application_credential" WHERE "application_credential"."user_id" = $1 ORDER BY "application_credential"."id" ASC"#,
                []
            ),
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "application_credential_role"."application_credential_id", "application_credential_role"."role_id" FROM "application_credential_role" WHERE "application_credential_role"."application_credential_id" IN ($1, $2)"#,
                []
            ),
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" WHERE "role"."id" IN ($1, $2, $3)"#,
                []
            ),
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "application_credential_access_rule"."application_credential_id", "application_credential_access_rule"."access_rule_id" FROM "application_credential_access_rule" WHERE "application_credential_access_rule"."application_credential_id" IN ($1, $2)"#,
                []
            ),
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "access_rule"."id", "access_rule"."service", "access_rule"."path", "access_rule"."method", "access_rule"."external_id", "access_rule"."user_id" FROM "access_rule" WHERE "access_rule"."id" IN ($1, $2)"#,
                []
            ),
        ]) {
            assert_eq!(
                l.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>(),
                r.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>()
            );
        }
    }
}
