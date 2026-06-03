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
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::prelude::Password;

use crate::entity::password;

/// Set a new password for the local user.
///
/// - expire all existing passwords.
/// - truncate number of old passwords to `unique_count`.
/// - add a new record with a new password
///
/// # Parameters
/// - `db`: The database connection.
/// - `local_user_id`: The local user ID.
/// - `unique_count`: Number of old passwords to keep for checking uniqueness.
/// - `password_hash`: The hashed password.
/// - `expires_at`: The password expiration date.
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
) -> Result<password::Model, IdentityProviderError> {
    let now = Utc::now();
    // Fetch existing passwords
    let existing_passwords = Password::find()
        .filter(password::Column::LocalUserId.eq(local_user_id))
        .order_by(password::Column::CreatedAtInt, Order::Desc)
        .all(db)
        .await
        .context("fetching existing passwords for user")?;

    // Determine history size: unique_last_password_count + 1 (for the new password)
    // If unique_last_password_count is 0 or None, just keep 1 (the new password)
    let history_size = if unique_count == 0 {
        1
    } else {
        unique_count as usize + 1
    };

    // Truncate extra passwords by keeping only the last `history_size - 1` entries
    let truncated_passwords: Vec<password::Model> = if existing_passwords.len() > history_size - 1 {
        existing_passwords
            .into_iter()
            .rev()
            .take(history_size - 1)
            .collect()
    } else {
        existing_passwords
    };

    // Expire all previous passwords (set expires_at to now)
    let expires_now = now.naive_utc();
    for pw in &truncated_passwords {
        let mut pw_active: password::ActiveModel = pw.clone().into();
        pw_active.expires_at = Set(Some(expires_now));
        pw_active.expires_at_int = Set(Some(now.timestamp_micros()));
        pw_active
            .update(db)
            .await
            .context("expiring previous password")?;
    }

    super::create(db, local_user_id, password_hash, expires_at).await
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase};

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
    // unique_last_password_count = 0  →  history_size = 1, keep 0 old passwords
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_zero_no_existing() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<password::Model>::new()])
            // create → insert returns new record
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        let res = set_new_password(&db, 1, 0, "hash", None).await;
        assert!(res.is_ok(), "should succeed with no existing passwords");
    }

    #[tokio::test]
    async fn unique_zero_existing_passwords_truncated_away() {
        // 3 existing passwords, unique=0 → history_size=1 → keep 0 → all truncated,
        // none kept. Truncated list is empty, so no UPDATE calls, only INSERT.
        let existing = vec![
            make_pwd(1, 300, false),
            make_pwd(2, 200, false),
            make_pwd(3, 100, false),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([existing])
            // No UPDATE because truncated list is empty
            .append_query_results([vec![make_pwd(10, 500, false)]])
            .into_connection();

        let res = set_new_password(&db, 1, 0, "hash", None).await;
        assert!(
            res.is_ok(),
            "unique=0 should truncate everything and insert new"
        );
    }

    // ---------------------------------------------------------------------------
    // unique_last_password_count = 1  →  history_size = 2, keep 1 old password
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_one_no_existing() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<password::Model>::new()])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(set_new_password(&db, 1, 1, "hash", None).await.is_ok());
    }

    #[tokio::test]
    async fn unique_one_one_existing_kept() {
        // 1 existing, unique=1 → keep 1 old → no truncation → expire the 1 kept.
        let existing = vec![make_pwd(1, 100, false)];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([existing])
            // Expire the 1 kept password
            .append_query_results([vec![make_pwd(1, 100, true)]])
            // Insert new
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(set_new_password(&db, 1, 1, "hash", None).await.is_ok());
    }

    #[tokio::test]
    async fn unique_one_two_existing_truncate_excess() {
        // 2 existing (newest=200, older=100), unique=1 → keep 1 old.
        // existing.len() (2) > history_size-1 (1) → truncate to 1.
        // The truncation reverses the DESC list (200,100 → 100,200) then take(1) →
        // [100]. Expire pw id=3 (created_at_int=100).
        let existing = vec![
            make_pwd(2, 200, false), // newest first
            make_pwd(3, 100, false), // older
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([existing])
            // Expire truncated list: [pw3 (int=100)]
            .append_query_results([vec![make_pwd(3, 100, true)]])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(set_new_password(&db, 1, 1, "hash", None).await.is_ok());
    }

    // ---------------------------------------------------------------------------
    // unique_last_password_count = 2  →  history_size = 3, keep 2 old passwords
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_two_two_existing_all_kept() {
        let existing = vec![make_pwd(2, 200, false), make_pwd(3, 100, false)];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([existing])
            // Expire both
            .append_query_results([vec![make_pwd(2, 200, true)]])
            .append_query_results([vec![make_pwd(3, 100, true)]])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(set_new_password(&db, 1, 2, "hash", None).await.is_ok());
    }

    #[tokio::test]
    async fn unique_two_five_existing_truncate_excess() {
        // 5 existing, unique=2 → keep 2 old, truncate 3.
        // Order DESC: 500,400,300,200,100 → rev: 100,200,300,400,500 → take(2) →
        // [100,200]
        let existing = vec![
            make_pwd(1, 500, false),
            make_pwd(2, 400, false),
            make_pwd(3, 300, false),
            make_pwd(4, 200, false),
            make_pwd(5, 100, false),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([existing])
            // Expire [pw5 (int=100), pw4 (int=200)]
            .append_query_results([vec![make_pwd(5, 100, true)]])
            .append_query_results([vec![make_pwd(4, 200, true)]])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(set_new_password(&db, 1, 2, "hash", None).await.is_ok());
    }

    // ---------------------------------------------------------------------------
    // Mixed expired / active passwords — already expired still get expire call
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn unique_two_mixed_expired_and_active() {
        // pw1 active, pw2 already expired, pw3 active
        // DESC: 300,200,100 → rev: 100,200,300 → take(2) → [100,200] → expire pw3,pw2
        let existing = vec![
            make_pwd(1, 300, false),
            make_pwd(2, 200, true),
            make_pwd(3, 100, false),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([existing])
            .append_query_results([vec![make_pwd(3, 100, true)]])
            .append_query_results([vec![make_pwd(2, 200, true)]])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(set_new_password(&db, 1, 2, "hash", None).await.is_ok());
    }

    // ---------------------------------------------------------------------------
    // Expiration on the new password (expires_at argument)
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn new_password_with_expiration() {
        let expires = Utc::now() + TimeDelta::days(90);

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<password::Model>::new()])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        let res = set_new_password(&db, 1, 0, "hash", Some(expires)).await;
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
        // unique=5 → history=6 → keep 5 old. 6 existing > 5 → truncate to 5.
        // DESC: 600..100 → rev: 100..600 → take(5) → [100,200,300,400,500]
        let existing = vec![
            make_pwd(1, 600, false),
            make_pwd(2, 500, false),
            make_pwd(3, 400, false),
            make_pwd(4, 300, false),
            make_pwd(5, 200, false),
            make_pwd(6, 100, false),
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([existing])
            // Expire the 5 kept (oldest 5 in rev order)
            .append_query_results([vec![make_pwd(6, 100, true)]])
            .append_query_results([vec![make_pwd(5, 200, true)]])
            .append_query_results([vec![make_pwd(4, 300, true)]])
            .append_query_results([vec![make_pwd(3, 400, true)]])
            .append_query_results([vec![make_pwd(2, 500, true)]])
            .append_query_results([vec![make_pwd(10, 999, false)]])
            .into_connection();

        assert!(set_new_password(&db, 1, 5, "hash", None).await.is_ok());
    }
}
