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
//! Update user properties.

use sea_orm::DatabaseConnection;
use sea_orm::TransactionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_config::Config;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::{UserResponse, UserUpdate};

use crate::entity::prelude::LocalUser;
use crate::entity::{local_user as db_local_user, user as db_user};
use crate::local_user;

/// Update an existing user.
///
/// # Parameters
/// - `conf`: The system configuration.
/// - `db`: The database connection.
/// - `user_id`: The ID of the user to update.
/// - `user`: The user update request.
///
/// # Returns
/// A `Result` containing the updated `UserResponse` if successful, or an
/// `Error`.
#[tracing::instrument(skip(conf, db))]
pub async fn update(
    conf: &Config,
    db: &DatabaseConnection,
    user_id: &str,
    user: UserUpdate,
) -> Result<UserResponse, IdentityProviderError> {
    let txn = db
        .begin()
        .await
        .context("starting transaction for updating user")?;

    // Fetch the existing user
    let existing_user = db_user::Entity::find_by_id(user_id)
        .one(&txn)
        .await
        .context("fetching user for update")?
        .ok_or(IdentityProviderError::UserNotFound(user_id.to_string()))?;

    // Build the update active model from the existing user
    let mut update_model: db_user::ActiveModel = existing_user.clone().into();

    // Update default_project_id if provided in the patch
    // user.default_project_id is Option<Option<String>> - inner None means clear,
    // inner Some(val) means set
    if let Some(Some(default_project_id)) = &user.default_project_id {
        update_model.default_project_id = Set(Some(default_project_id.clone()));
    } else if let Some(None) = &user.default_project_id {
        update_model.default_project_id = Set(None);
    }

    // Update enabled flag if provided in the patch
    if let Some(enabled) = user.enabled {
        update_model.enabled = Set(Some(enabled));
    }

    // Update extra properties if provided in the patch
    if !user.extra.is_empty() {
        update_model.extra = Set(Some(serde_json::to_string(&user.extra)?));
    }

    // Update the main user record
    let _ = update_model
        .update(&txn)
        .await
        .context("updating user entry")?;

    // Only load local user if we need to update name or password
    if user.name.is_some() || user.password.is_some() {
        // Load local user for name and password updates
        let mut local_user_result = LocalUser::find()
            .filter(db_local_user::Column::UserId.eq(user_id))
            .one(&txn)
            .await
            .context("fetching local user for update")?;

        // If local_user doesn't exist, create one (name will be updated if provided)
        if local_user_result.is_none() {
            local_user_result = Some(
                db_local_user::ActiveModel {
                    id: NotSet,
                    user_id: Set(user_id.to_string()),
                    domain_id: Set(existing_user.domain_id.clone()),
                    // Will be overwritten by the name update below if provided
                    name: Set(user.name.clone().unwrap_or_default()),
                    failed_auth_count: NotSet,
                    failed_auth_at: NotSet,
                }
                .insert(&txn)
                .await
                .context("inserting new local user record")?,
            );
        }

        if let Some(local_user_model) = &local_user_result {
            // Update name if provided in the patch
            if let Some(ref name) = user.name {
                let mut lu_active: db_local_user::ActiveModel = local_user_model.clone().into();
                lu_active.name = Set(name.clone());
                lu_active
                    .update(&txn)
                    .await
                    .context("updating local user entry")?;
            }

            // Update password if provided in the patch
            if let Some(ref new_password) = user.password {
                local_user::set_new_password(
                    &txn,
                    conf,
                    local_user_model.id,
                    secrecy::SecretString::from(new_password.as_str()),
                )
                .await?;
            }
        }
    }

    txn.commit()
        .await
        .context("committing the user update transaction")?;

    // Fetch and return the updated user using existing get logic
    let updated_user = crate::user::get(conf, db, user_id)
        .await?
        .ok_or(IdentityProviderError::UserNotFound(user_id.to_string()))?;

    Ok(updated_user)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use crate::entity::password as db_password;
    use crate::entity::user_option as db_user_option;
    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::identity::UserUpdate;

    use super::*;
    use crate::local_user::tests::{get_local_user_mock, get_local_user_with_password_mock};

    use crate::user::tests::get_user_mock;

    fn make_pwd(id: i32, created_at_int: i64, expired: bool) -> db_password::Model {
        let now = chrono::Utc::now();
        let (ea, eai) = if expired {
            (
                Some(chrono::DateTime::<chrono::Utc>::MIN_UTC.naive_utc()),
                Some(chrono::DateTime::<chrono::Utc>::MIN_UTC.timestamp_micros()),
            )
        } else {
            (None, None)
        };
        db_password::Model {
            id,
            local_user_id: 1,
            self_service: false,
            expires_at: ea,
            password_hash: Some("fake_hash".into()),
            created_at: now.naive_utc(),
            created_at_int,
            expires_at_int: eai,
        }
    }

    #[tokio::test]
    async fn test_update_enabled_only() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Transaction queries:
            // 1. Fetch existing user for update
            .append_query_results([vec![get_user_mock("1")]])
            // 2. Update user entry returns updated user
            .append_query_results([vec![get_user_mock("1")]])
            // Post-transaction queries (user::get()):
            // 3. Fetch user by ID
            .append_query_results([vec![get_user_mock("1")]])
            // 4. Fetch user options (empty)
            .append_query_results([Vec::<db_user_option::Model>::new()])
            // 5. Fetch local user with passwords
            .append_query_results([get_local_user_with_password_mock("1", 1)])
            .into_connection();

        let req = UserUpdate {
            enabled: Some(true),
            ..Default::default()
        };

        let result = update(&Config::default(), &db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Transaction queries:
            // 1. Fetch existing user for update
            .append_query_results([vec![get_user_mock("1")]])
            // 2. Update user entry returns updated user
            .append_query_results([vec![get_user_mock("1")]])
            // 3. Fetch local_user for name update
            .append_query_results([vec![get_local_user_mock("1")]])
            // 4. Update local_user entry returns updated local user
            .append_query_results([vec![get_local_user_mock("1")]])
            // Post-transaction queries (user::get()):
            // 5. Fetch user by ID
            .append_query_results([vec![get_user_mock("1")]])
            // 6. Fetch user options (empty)
            .append_query_results([Vec::<db_user_option::Model>::new()])
            // 7. Fetch local user with passwords
            .append_query_results([get_local_user_with_password_mock("1", 1)])
            .into_connection();

        let req = UserUpdate {
            name: Some("new_name".to_string()),
            ..Default::default()
        };

        let result = update(&Config::default(), &db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_password_no_existing() {
        // Config: unique_last_password_count=0, no password expiry
        let mut conf = Config::default();
        conf.security_compliance.unique_last_password_count = Some(0);

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Transaction queries:
            // 1. Fetch existing user for update
            .append_query_results([vec![get_user_mock("1")]])
            // 2. Update user entry (no-op but still issues UPDATE)
            .append_query_results([vec![get_user_mock("1")]])
            // 3. Fetch local_user
            .append_query_results([vec![get_local_user_mock("1")]])
            // 4. Fetch existing passwords (empty)
            .append_query_results([Vec::<db_password::Model>::new()])
            // 5. Insert new password
            .append_query_results([vec![make_pwd(10, 999, false)]])
            // Commit
            // Post-transaction queries (user::get()):
            // 6. Fetch user by ID
            .append_query_results([vec![get_user_mock("1")]])
            // 7. Fetch user options (empty)
            .append_query_results([Vec::<db_user_option::Model>::new()])
            // 8. Fetch local user with passwords
            .append_query_results([get_local_user_with_password_mock("1", 1)])
            .into_connection();

        let req = UserUpdate {
            password: Some("new_password".to_string()),
            ..Default::default()
        };

        let result = update(&conf, &db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_password_with_history_truncation() {
        // Config: unique_last_password_count=1 means keep 1 old password
        let mut conf = Config::default();
        // unique=1 → history=2 → keep 1 old. 3 existing → truncate oldest 2.
        // Expire the 1 kept password, then insert new.
        conf.security_compliance.unique_last_password_count = Some(1);

        let existing = vec![
            db_password::ModelBuilder::default()
                .id(1)
                .created_at_int(300)
                .local_user_id(1)
                .build()
                .unwrap(),
            db_password::ModelBuilder::default()
                .id(2)
                .created_at_int(200)
                .local_user_id(1)
                .build()
                .unwrap(),
            db_password::ModelBuilder::default()
                .id(3)
                .created_at_int(100)
                .local_user_id(1)
                .build()
                .unwrap(),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. Fetch existing user
            .append_query_results([vec![get_user_mock("1")]])
            // 2. Update user entry
            .append_query_results([vec![get_user_mock("1")]])
            // 3. Fetch local_user
            .append_query_results([vec![get_local_user_mock("1")]])
            // 4. Fetch existing passwords (3, DESC by created_at_int)
            .append_query_results([existing])
            // 5. Expire the 1 kept password (truncated list after rev+take(1))
            .append_query_results([vec![
                db_password::ModelBuilder::default()
                    .id(3)
                    .created_at_int(100)
                    .local_user_id(1)
                    .build()
                    .unwrap(),
            ]])
            // 6. Insert new password
            .append_query_results([vec![make_pwd(10, 999, false)]])
            // Post-transaction:
            // 7. Fetch user by ID
            .append_query_results([vec![get_user_mock("1")]])
            // 8. Fetch user options (empty)
            .append_query_results([Vec::<db_user_option::Model>::new()])
            // 9. Fetch local user with passwords
            .append_query_results([get_local_user_with_password_mock("1", 1)])
            .into_connection();

        let req = UserUpdate {
            password: Some("new_password".to_string()),
            ..Default::default()
        };

        let result = update(&conf, &db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_password_expires_days_set() {
        // Config: password_expires_days=90 sets expires_at on new password
        let mut conf = Config::default();
        conf.security_compliance.unique_last_password_count = Some(0);
        conf.security_compliance.password_expires_days = Some(90);

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. Fetch existing user
            .append_query_results([vec![get_user_mock("1")]])
            // 2. Update user entry
            .append_query_results([vec![get_user_mock("1")]])
            // 3. Fetch local_user
            .append_query_results([vec![get_local_user_mock("1")]])
            // 4. Fetch existing passwords (empty)
            .append_query_results([Vec::<db_password::Model>::new()])
            // 5. Insert new password (with expires_at set by config)
            .append_query_results([vec![
                db_password::ModelBuilder::default()
                    .id(10)
                    .created_at_int(1000)
                    .local_user_id(1)
                    .build()
                    .unwrap(),
            ]])
            // Post-transaction:
            // 6. Fetch user by ID
            .append_query_results([vec![get_user_mock("1")]])
            // 7. Fetch user options (empty)
            .append_query_results([Vec::<db_user_option::Model>::new()])
            // 8. Fetch local user with passwords (1 password with expiry info)
            .append_query_results([get_local_user_with_password_mock("1", 1)])
            .into_connection();

        let req = UserUpdate {
            password: Some("new_password".to_string()),
            ..Default::default()
        };

        let result = update(&conf, &db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_name_and_password() {
        let mut conf = Config::default();
        conf.security_compliance.unique_last_password_count = Some(0);

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. Fetch existing user
            .append_query_results([vec![get_user_mock("1")]])
            // 2. Update user entry
            .append_query_results([vec![get_user_mock("1")]])
            // 3. Fetch local_user
            .append_query_results([vec![get_local_user_mock("1")]])
            // 4. Update local_user (name change)
            .append_query_results([vec![get_local_user_mock("1")]])
            // 5. Fetch existing passwords (empty)
            .append_query_results([Vec::<db_password::Model>::new()])
            // 6. Insert new password
            .append_query_results([vec![make_pwd(10, 999, false)]])
            // Post-transaction:
            // 7. Fetch user by ID
            .append_query_results([vec![get_user_mock("1")]])
            // 8. Fetch user options (empty)
            .append_query_results([Vec::<db_user_option::Model>::new()])
            // 9. Fetch local user with passwords
            .append_query_results([get_local_user_with_password_mock("1", 1)])
            .into_connection();

        let req = UserUpdate {
            name: Some("new_name".to_string()),
            password: Some("new_password".to_string()),
            ..Default::default()
        };

        let result = update(&conf, &db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }
}
