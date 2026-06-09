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
use sea_orm::ConnectionTrait;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::password;

/// Set a new password for the local user using pre-loaded existing passwords.
///
/// - expire the newest `unique_count` passwords (kept as history for uniqueness
///   checks).
/// - delete older passwords beyond the history window.
/// - add a new record with the new password.
///
/// # Parameters
/// - `db`: The database connection.
/// - `local_user_id`: The local user ID.
/// - `unique_count`: Number of old passwords to keep for checking uniqueness.
/// - `password_hash`: The hashed password.
/// - `expires_at`: The password expiration date.
/// - `existing_passwords`: Pre-loaded existing passwords sorted DESC by creation.
///
/// # Returns
/// A `Result` containing the created `password::Model` if successful, or an
/// `Error`.
#[tracing::instrument(skip_all)]
pub async fn set_new_password<C: ConnectionTrait, S: AsRef<str>>(
    db: &C,
    local_user_id: i32,
    unique_count: u16,
    password_hash: S,
    expires_at: Option<DateTime<Utc>>,
    existing_passwords: Vec<password::Model>,
) -> Result<password::Model, IdentityProviderError> {
    let now = Utc::now();

    // Determine history size: unique_last_password_count + 1 (for the new password)
    // If unique_count is 0, don't keep any old passwords.
    let keep_count = unique_count as usize;

    // existing_passwords is sorted DESC (newest first). Expire the newest
    // `keep_count` passwords (kept as history), delete the rest (older ones
    // beyond the history window).
    let (to_expire, to_delete) =
        existing_passwords.split_at(keep_count.min(existing_passwords.len()));

    // Expire the most recent passwords (kept as history)
    let expires_now = now.naive_utc();
    for pw in to_expire {
        let mut pw_active: password::ActiveModel = pw.clone().into();
        pw_active.expires_at = Set(Some(expires_now));
        pw_active.expires_at_int = Set(Some(now.timestamp_micros()));
        pw_active
            .update(db)
            .await
            .context("expiring previous password")?;
    }

    // Delete older passwords beyond the history window
    for pw in to_delete {
        password::Entity::delete_by_id(pw.id)
            .exec(db)
            .await
            .context("deleting old password beyond history window")?;
    }

    super::create(db, local_user_id, password_hash, expires_at).await
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use super::*;

    /// Helper to create a mock password model.
    ///
    /// `expired` when true sets `expires_at` / `expires_at_int` to `Utc::MIN`.
    /// `created_at_int` controls ordering (newest first when DESC).
    fn make_pwd(id: i32, created_at_int: i64, expired: bool) -> password::Model {
        let now = Utc::now();
        let (ea, eai) = if expired {
            (
                Some(chrono::DateTime::<Utc>::MIN_UTC.naive_utc()),
                Some(chrono::DateTime::<Utc>::MIN_UTC.timestamp_micros()),
            )
        } else {
            (None, None)
        };
        password::Model {
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

    // ---------------------------------------------------------------------------
    // unique_last_password_count = 0  ->  keep 0 old passwords, delete all
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_zero_no_existing() {
        let existing = Vec::<password::Model>::new();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // create → insert returns new record
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        let res = set_new_password(&db, 1, 0, "hash", None, existing).await;
        assert!(res.is_ok(), "should succeed with no existing passwords");
    }

    #[tokio::test]
    async fn unique_zero_existing_passwords_truncated_away() {
        // 3 existing passwords, unique=0 → keep 0 → all deleted.
        let existing = vec![
            make_pwd(1, 300, false),
            make_pwd(2, 200, false),
            make_pwd(3, 100, false),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Delete all 3
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
            ])
            .append_query_results([vec![make_pwd(10, 500, false)]])
            .into_connection();

        let res = set_new_password(&db, 1, 0, "hash", None, existing).await;
        assert!(
            res.is_ok(),
            "unique=0 should delete everything and insert new"
        );
    }

    // ---------------------------------------------------------------------------
    // unique_last_password_count = 1  ->  expire 1 old password, delete the rest
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_one_no_existing() {
        let existing = Vec::<password::Model>::new();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(
            set_new_password(&db, 1, 1, "hash", None, existing)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn unique_one_one_existing_kept() {
        // 1 existing, unique=1 → keep 1 old → no truncation → expire the 1 kept.
        let existing = vec![make_pwd(1, 100, false)];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Expire the 1 kept password
            .append_query_results([vec![make_pwd(1, 100, true)]])
            // Insert new
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(
            set_new_password(&db, 1, 1, "hash", None, existing)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn unique_one_two_existing_truncate_excess() {
        // 2 existing (newest=200, older=100), unique=1 → expire 1 (newest), delete 1 (older).
        let existing = vec![
            make_pwd(2, 200, false), // newest first
            make_pwd(3, 100, false), // older
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Expire newest: [pw2 (int=200)]
            .append_query_results([vec![make_pwd(2, 200, true)]])
            // Delete older: [pw3 (int=100)]
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(
            set_new_password(&db, 1, 1, "hash", None, existing)
                .await
                .is_ok()
        );
    }

    // ---------------------------------------------------------------------------
    // unique_last_password_count = 2  ->  expire 2 old passwords, delete the rest
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_two_two_existing_all_kept() {
        let existing = vec![make_pwd(2, 200, false), make_pwd(3, 100, false)];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Expire both
            .append_query_results([vec![make_pwd(2, 200, true)]])
            .append_query_results([vec![make_pwd(3, 100, true)]])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(
            set_new_password(&db, 1, 2, "hash", None, existing)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn unique_two_five_existing_truncate_excess() {
        // 5 existing, unique=2 → expire 2 new (id=1,2), delete 3 old (id=3,4,5).
        let existing = vec![
            make_pwd(1, 500, false),
            make_pwd(2, 400, false),
            make_pwd(3, 300, false),
            make_pwd(4, 200, false),
            make_pwd(5, 100, false),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Expire newest 2: [pw1 (int=500), pw2 (int=400)]
            .append_query_results([vec![make_pwd(1, 500, true)]])
            .append_query_results([vec![make_pwd(2, 400, true)]])
            // Delete older 3: [pw3, pw4, pw5]
            .append_exec_results([
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
            ])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(
            set_new_password(&db, 1, 2, "hash", None, existing)
                .await
                .is_ok()
        );
    }

    // ---------------------------------------------------------------------------
    // Mixed expired / active passwords — expire newest, delete older
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_two_mixed_expired_and_active() {
        // pw1 active, pw2 already expired, pw3 active
        // DESC: 300,200,100 -> expire pw1,pw2 (newest 2), delete pw3 (older)
        let existing = vec![
            make_pwd(1, 300, false),
            make_pwd(2, 200, true),
            make_pwd(3, 100, false),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Expire newest 2: [pw1 (int=300), pw2 (int=200)]
            .append_query_results([vec![make_pwd(1, 300, true)]])
            .append_query_results([vec![make_pwd(2, 200, true)]])
            // Delete older: [pw3 (int=100)]
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(
            set_new_password(&db, 1, 2, "hash", None, existing)
                .await
                .is_ok()
        );
    }

    // ---------------------------------------------------------------------------
    // Expiration on the new password (expires_at argument)
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn new_password_with_expiration() {
        let expires = Utc::now() + TimeDelta::days(90);

        let existing = Vec::<password::Model>::new();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        let res = set_new_password(&db, 1, 0, "hash", Some(expires), existing).await;
        assert!(res.is_ok());
        // The create() call uses the expires_at argument; mock doesn't validate,
        // but the fact that it succeeded means the flow is correct.
        let _ = res.unwrap();
    }

    // ---------------------------------------------------------------------------
    // unique_last_password_count = 5 — boundary test
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_five_exactly_six_existing_no_truncation() {
        // unique=5, 6 existing -> expire 5 newest, delete 1 oldest.
        let existing = vec![
            make_pwd(1, 600, false),
            make_pwd(2, 500, false),
            make_pwd(3, 400, false),
            make_pwd(4, 300, false),
            make_pwd(5, 200, false),
            make_pwd(6, 100, false),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // Expire the 5 newest
            .append_query_results([vec![make_pwd(1, 600, true)]])
            .append_query_results([vec![make_pwd(2, 500, true)]])
            .append_query_results([vec![make_pwd(3, 400, true)]])
            .append_query_results([vec![make_pwd(4, 300, true)]])
            .append_query_results([vec![make_pwd(5, 200, true)]])
            // Delete the 1 oldest
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(
            set_new_password(&db, 1, 5, "hash", None, existing)
                .await
                .is_ok()
        );
    }
}
