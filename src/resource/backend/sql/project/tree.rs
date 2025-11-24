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

use crate::db::entity::prelude::Project as DbProject;
use crate::resource::backend::error::{ResourceDatabaseError, db_err};
use crate::resource::types::Project;

pub async fn get_project_parents<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Vec<Project>>, ResourceDatabaseError> {
    let mut res: Vec<Project> = Vec::new();
    let mut project_id: Option<String> = Some(id.as_ref().to_string());
    while let Some(pid) = project_id {
        let project = DbProject::find_by_id(pid.clone())
            .one(db)
            .await
            .map_err(|err| db_err(err, "resolving project parents"))?;
        if pid == id.as_ref() && project.is_none() {
            return Ok(None);
        }
        if let Some(p) = &project
            && pid != id.as_ref()
        {
            res.push(p.clone().try_into()?);
        }
        project_id = project.and_then(|project| project.parent_id);
    }

    Ok(Some(res))
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::db::entity::project;

    use super::*;
    use crate::resource::types::Project;

    pub(super) fn get_mock<I: AsRef<str>, P: AsRef<str>>(
        id: I,
        parent_id: Option<P>,
    ) -> project::Model {
        project::Model {
            id: id.as_ref().to_string(),
            name: "project_name".into(),
            extra: None,
            description: Some("description".into()),
            enabled: Some(true),
            domain_id: "domain_id".into(),
            parent_id: parent_id.as_ref().map(|val| val.as_ref().into()),
            is_domain: parent_id.as_ref().is_some(),
        }
    }

    #[tokio::test]
    async fn test_get_project_parents() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("3", Some("2"))]])
            .append_query_results([vec![get_mock("2", Some("1"))]])
            .append_query_results([vec![get_mock("1", Some("domain_id"))]])
            .append_query_results([vec![get_mock("domain_id", None::<&str>)]])
            .into_connection();
        assert_eq!(
            get_project_parents(&db, "3").await.unwrap().unwrap(),
            vec![
                Project {
                    id: "2".into(),
                    parent_id: Some("1".into()),
                    name: "project_name".into(),
                    domain_id: "domain_id".into(),
                    enabled: true,
                    description: Some("description".into()),
                    extra: None
                },
                Project {
                    id: "1".into(),
                    parent_id: Some("domain_id".into()),
                    name: "project_name".into(),
                    domain_id: "domain_id".into(),
                    enabled: true,
                    description: Some("description".into()),
                    extra: None
                },
                Project {
                    id: "domain_id".into(),
                    parent_id: None,
                    name: "project_name".into(),
                    domain_id: "domain_id".into(),
                    enabled: true,
                    description: Some("description".into()),
                    extra: None
                }
            ]
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 LIMIT $2"#,
                    ["3".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 LIMIT $2"#,
                    ["2".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 LIMIT $2"#,
                    ["domain_id".into(), 1u64.into()]
                ),
            ]
        );
    }
}
