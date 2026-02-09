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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;

use crate::db::entity::project as db_project;
use crate::error::DbContextExt;
use crate::resource::backend::error::ResourceDatabaseError;
use crate::resource::types::{Project, ProjectCreate};

pub async fn create<C>(db: &C, project: ProjectCreate) -> Result<Project, ResourceDatabaseError>
where
    C: ConnectionTrait,
{
    TryInto::<db_project::ActiveModel>::try_into(project)?
        .insert(db)
        .await
        .context("persisting new project data")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_project_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_project_mock("1")]])
            .into_connection();

        let req = ProjectCreate {
            description: Some("description".into()),
            domain_id: "foo_domain".into(),
            enabled: true,
            extra: None,
            id: Some("1".into()),
            is_domain: false,
            name: "project_name".into(),
            parent_id: Some("parent_id".into()),
        };

        assert_eq!(
            create(&db, req).await.unwrap(),
            get_project_mock("1").try_into().unwrap()
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "project" ("id", "name", "extra", "description", "enabled", "domain_id", "parent_id", "is_domain") VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING "id", "name", "extra", "description", "enabled", "domain_id", "parent_id", "is_domain""#,
                [
                    "1".into(),
                    "project_name".into(),
                    "{}".into(),
                    "description".into(),
                    true.into(),
                    "foo_domain".into(),
                    "parent_id".into(),
                    false.into()
                ]
            ),]
        );
    }
}
