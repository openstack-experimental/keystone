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

use async_trait::async_trait;

mod domain;
mod project;

use super::super::types::*;
use crate::config::Config;
use crate::keystone::ServiceState;
use crate::resource::ResourceProviderError;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

#[async_trait]
impl ResourceBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Get single domain by ID
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        Ok(domain::get_domain_by_id(&self.config, &state.db, domain_id).await?)
    }

    /// Get single domain by Name
    async fn get_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        Ok(domain::get_domain_by_name(&self.config, &state.db, domain_name).await?)
    }

    /// Get single project by ID
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        Ok(project::get_project(&self.config, &state.db, project_id).await?)
    }

    /// Get single project by Name and Domain ID
    async fn get_project_by_name<'a>(
        &self,
        state: &ServiceState,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        Ok(project::get_project_by_name(&self.config, &state.db, name, domain_id).await?)
    }

    /// Get project parents
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        Ok(project::get_project_parents(&state.db, project_id).await?)
    }
}

//#[cfg(test)]
//mod tests {
//    #![allow(clippy::derivable_impls)]
//    use chrono::Local;
//    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
//
//    use crate::db::entity::{local_user, password, user, user_option};
//    use crate::identity::Config;
//
//    use super::*;
//
//    fn get_user_mock(user_id: String) -> user::Model {
//        user::Model {
//            id: user_id.clone(),
//            domain_id: "foo_domain".into(),
//            enabled: Some(true),
//            ..Default::default()
//        }
//    }
//
//    fn get_local_user_with_password_mock(
//        user_id: String,
//        cnt_password: usize,
//    ) -> Vec<(local_user::Model, password::Model)> {
//        let lu = local_user::Model {
//            user_id: user_id.clone(),
//            domain_id: "foo_domain".into(),
//            name: "Apple Cake".to_owned(),
//            ..Default::default()
//        };
//        let mut passwords: Vec<password::Model> = Vec::new();
//        for i in 0..cnt_password {
//            passwords.push(password::Model {
//                id: i as i32,
//                local_user_id: 1,
//                expires_at: None,
//                self_service: false,
//                password_hash: None,
//                created_at: Local::now().naive_utc(),
//                created_at_int: 12345,
//                expires_at_int: None,
//            });
//        }
//        passwords
//            .into_iter()
//            .map(|x| (lu.clone(), x.clone()))
//            .collect()
//    }
//
//    #[tokio::test]
//    async fn test_get_user_local() {
//        // Create MockDatabase with mock query results
//        let db = MockDatabase::new(DatabaseBackend::Postgres)
//            .append_query_results([
//                // First query result - select user itself
//                vec![get_user_mock("1".into())],
//            ])
//            .append_query_results([
//                //// Second query result - user options
//                vec![user_option::Model {
//                    user_id: "1".into(),
//                    option_id: "1000".into(),
//                    option_value: Some("true".into()),
//                }],
//            ])
//            .append_query_results([
//                // Third query result - local user with passwords
//                get_local_user_with_password_mock("1".into(), 1),
//            ])
//            .into_connection();
//        let config = Config::default();
//        assert_eq!(
//            get_user(&config, &db, "1".into()).await.unwrap().unwrap(),
//            User {
//                id: "1".into(),
//                domain_id: "foo_domain".into(),
//                name: "Apple Cake".to_owned(),
//                enabled: true,
//                options: UserOptions {
//                    ignore_change_password_upon_first_use: Some(true),
//                    ..Default::default()
//                },
//                ..Default::default()
//            }
//        );
//
//        // Checking transaction log
//        assert_eq!(
//            db.into_transaction_log(),
//            [
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "user"."id", "user"."extra", "user"."enabled", "user"."default_project_id", "user"."created_at", "user"."last_active_at", "user"."domain_id" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
//                    ["1".into(), 1u64.into()]
//                ),
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" INNER JOIN "user" ON "user"."id" = "user_option"."user_id" WHERE "user"."id" = $1"#,
//                    ["1".into()]
//                ),
//                Transaction::from_sql_and_values(
//                    DatabaseBackend::Postgres,
//                    r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC"#,
//                    ["1".into()]
//                ),
//            ]
//        );
//    }
//}
