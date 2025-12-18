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
use serde_json::json;
use uuid::Uuid;

use crate::assignment::backend::error::{AssignmentDatabaseError, db_err};
use crate::assignment::types::role::{Role, RoleCreate};
use crate::db::entity::role as db_role;

/// Create a new role
pub async fn create(
    db: &DatabaseConnection,
    role: RoleCreate, // ← Using RoleCreate instead of Role
) -> Result<Role, AssignmentDatabaseError> {
    db_role::ActiveModel {
        id: Set(role
            // Use provided ID or generate a new UUID as fallback
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().simple().to_string())),
        name: Set(role.name.clone()),
        domain_id: Set(role
            .domain_id
            .clone()
            .unwrap_or_else(|| super::NULL_DOMAIN_ID.to_string())),
        description: Set(role.description.clone()),
        extra: Set(Some(serde_json::to_string(
            &role.extra.as_ref().or(Some(&json!({}))),
        )?)),
    }
    .insert(db)
    .await
    .map_err(|err| db_err(err, "creating role"))?
    .try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::json;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_role::Model {
                id: "role-123".into(),
                domain_id: "default".into(),
                name: "Test Role".into(),
                description: Some("A role for testing".into()),
                extra: Some(r#"{"key":"value"}"#.into()),
            }]])
            .into_connection();

        let role_create = RoleCreate {
            id: Some("role-123".to_string()),
            name: "Test Role".to_string(),
            domain_id: Some("default".to_string()),
            description: Some("A role for testing".to_string()),
            extra: Some(json!({"key": "value"})),
        };

        let created = create(&db, role_create).await.unwrap();

        assert_eq!(created.id, "role-123");
        assert_eq!(created.name, "Test Role");
        assert_eq!(created.domain_id.as_deref(), Some("default"));
        assert_eq!(created.description.as_deref(), Some("A role for testing"));
        assert!(created.extra.is_some());
        assert_eq!(created.extra.as_ref().unwrap()["key"], "value");
    }

    #[tokio::test]
    async fn test_create_without_domain() {
        // When domain_id is None, NULL_DOMAIN_ID should be used
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_role::Model {
                id: "role-1".into(),
                domain_id: super::super::NULL_DOMAIN_ID.into(),
                name: "Global Role".into(),
                description: None,
                extra: None,
            }]])
            .into_connection();

        let role_create = RoleCreate {
            id: Some("role-1".to_string()),
            name: "Global Role".to_string(),
            domain_id: None, // ← No domain
            description: None,
            extra: None,
        };

        let created = create(&db, role_create).await.unwrap();

        assert_eq!(created.name, "Global Role");
        // domain_id should be None in the returned Role (because TryFrom filters NULL_DOMAIN_ID)
        assert_eq!(created.domain_id, None);
    }

    #[tokio::test]
    async fn test_create_with_extra() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_role::Model {
                id: "role-with-extra".into(),
                domain_id: "default".into(),
                name: "Role With Extra".into(),
                description: None,
                extra: Some(r#"{"custom":"data","count":42}"#.into()),
            }]])
            .into_connection();

        let role_create = RoleCreate {
            id: Some("role-with-extra".to_string()),
            name: "Role With Extra".to_string(),
            domain_id: Some("default".to_string()),
            description: None,
            extra: Some(json!({
                "custom": "data",
                "count": 42
            })),
        };

        let created = create(&db, role_create).await.unwrap();

        assert_eq!(created.name, "Role With Extra");
        assert!(created.extra.is_some());
        assert_eq!(created.extra.as_ref().unwrap()["custom"], "data");
        assert_eq!(created.extra.as_ref().unwrap()["count"], 42);
    }
}
