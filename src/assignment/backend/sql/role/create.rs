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

use crate::assignment::backend::error::{db_err, AssignmentDatabaseError};
use crate::assignment::types::role::{Role, RoleCreate};
use crate::config::Config;
use crate::db::entity::role as db_role;

/// Create a new role
pub async fn create(
    _conf: &Config,
    db: &DatabaseConnection,
    role: &RoleCreate,  // ← Using RoleCreate instead of Role
) -> Result<Role, AssignmentDatabaseError> {
    // Serialize extra field if present
    let extra_json = role
        .extra
        .as_ref()
        .map(|v| serde_json::to_string(v))
        .transpose()
        .map_err(|err| {
            AssignmentDatabaseError::SerializationError(format!(
                "failed to serialize role extra: {}",
                err
            ))
        })?;

    // Generate ID if not provided
    let role_id = role.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Create active model
    let entry = db_role::ActiveModel {
        id: Set(role_id),
        name: Set(role.name.clone()),
        domain_id: Set(role.domain_id.clone().unwrap_or_else(|| super::NULL_DOMAIN_ID.to_string())),
        description: Set(role.description.clone()),
        extra: Set(extra_json),
    };

    // Insert into database
    let created: db_role::Model = entry
        .insert(db)
        .await
        .map_err(|err| db_err(err, "creating role"))?;

    // Convert to domain type
    created.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{DatabaseBackend, MockDatabase};
    use serde_json::json;

    fn get_role_mock(id: String, name: String) -> db_role::Model {
        db_role::Model {
            id: id.clone(),
            domain_id: "default".into(),
            name: name.clone(),
            description: Some("Test role".into()),
            extra: Some(r#"{"key":"value"}"#.into()),
        }
    }

    #[tokio::test]
    async fn test_create_with_id() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_mock("test-role".into(), "Test Role".into())]])
            .into_connection();

        let config = Config::default();
        let role_create = RoleCreate {
            id: Some("test-role".to_string()),
            name: "Test Role".to_string(),
            domain_id: Some("default".to_string()),
            description: Some("Test role".to_string()),
            extra: Some(json!({"key": "value"})),
        };

        let created = create(&config, &db, &role_create).await.unwrap();

        assert_eq!(created.id, "test-role");
        assert_eq!(created.name, "Test Role");
        assert_eq!(created.domain_id, Some("default".to_string()));
    }

    #[tokio::test]
    async fn test_create_without_id() {
        // When id is None, a UUID should be generated
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_role::Model {
                id: uuid::Uuid::new_v4().to_string(),
                domain_id: "default".into(),
                name: "Auto ID Role".into(),
                description: None,
                extra: None,
            }]])
            .into_connection();

        let config = Config::default();
        let role_create = RoleCreate {
            id: None,  // ← No ID provided
            name: "Auto ID Role".to_string(),
            domain_id: Some("default".to_string()),
            description: None,
            extra: None,
        };

        let created = create(&config, &db, &role_create).await.unwrap();

        assert_eq!(created.name, "Auto ID Role");
        assert!(!created.id.is_empty());  // ID should be generated
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

        let config = Config::default();
        let role_create = RoleCreate {
            id: Some("role-1".to_string()),
            name: "Global Role".to_string(),
            domain_id: None,  // ← No domain
            description: None,
            extra: None,
        };

        let created = create(&config, &db, &role_create).await.unwrap();

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

        let config = Config::default();
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

        let created = create(&config, &db, &role_create).await.unwrap();

        assert_eq!(created.name, "Role With Extra");
        assert!(created.extra.is_some());
        assert_eq!(created.extra.as_ref().unwrap()["custom"], "data");
        assert_eq!(created.extra.as_ref().unwrap()["count"], 42);
    }
}