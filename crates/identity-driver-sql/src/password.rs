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
use secrecy::ExposeSecret;
use secrecy::SecretString;

use openstack_keystone_config::Config;
use openstack_keystone_core::common::password_hashing;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::UserResponseBuilder;

use crate::entity::password as db_password;

mod check_history;
mod create;
mod list;
mod set;

pub use create::create;
pub use list::list;

use sea_orm::ConnectionTrait;

/// Set a new password for the local user using pre-loaded existing passwords.
///
/// - check password history for reuse (reject if match).
/// - expire the newest `unique_count` passwords (kept as history).
/// - delete older passwords beyond the history window.
/// - hash and store the new password.
///
/// # Parameters
/// - `db`: The database connection.
/// - `conf`: The service configuration.
/// - `local_user_id`: The local user ID.
/// - `password`: The plaintext password to set.
/// - `existing_passwords`: Pre-loaded existing passwords sorted DESC by creation.
///
/// # Returns
/// A `Result` containing the created `db_password::Model` if successful, or an
/// `Error`.
pub async fn set_new_password<C: ConnectionTrait>(
    db: &C,
    conf: &Config,
    local_user_id: i32,
    password: SecretString,
    existing_passwords: Vec<db_password::Model>,
) -> Result<db_password::Model, IdentityProviderError> {
    check_history::check_password_history(conf, &existing_passwords, &password).await?;

    let now = Utc::now();
    let unique_count = conf
        .security_compliance
        .unique_last_password_count
        .unwrap_or(0);
    let hashed_password = password_hashing::hash_password(conf, password.expose_secret())
        .await
        .map_err(IdentityProviderError::password_hash)?;

    let expires_at = conf.security_compliance.get_password_expires_at(now);
    set::set_new_password(
        db,
        local_user_id,
        unique_count,
        hashed_password,
        expires_at,
        existing_passwords,
    )
    .await
}

/// Verify whether the password has expired or not.
///
/// # Parameters
/// - `password_entry`: The password entry to check.
///
/// # Returns
/// A `Result` containing a boolean indicating if the password has expired, or
/// an `Error`.
pub(super) fn is_password_expired(
    password_entry: &db_password::Model,
) -> Result<bool, IdentityProviderError> {
    if let Some(expires) = password_entry
        .expires_at_int
        .and_then(DateTime::from_timestamp_secs)
        .or_else(|| password_entry.expires_at.map(|val| val.and_utc()))
    {
        return Ok(expires <= Utc::now());
    }
    Ok(false)
}

pub trait MergePasswordData {
    fn merge_passwords_data<I>(&mut self, passwords: I) -> &mut Self
    where
        I: IntoIterator<Item = db_password::Model>;
}

impl MergePasswordData for UserResponseBuilder {
    /// Merge password data into the user response builder.
    ///
    /// # Parameters
    /// - `passwords`: An iterator of password models.
    ///
    /// # Returns
    /// A mutable reference to the builder.
    fn merge_passwords_data<I>(&mut self, passwords: I) -> &mut Self
    where
        I: IntoIterator<Item = db_password::Model>,
    {
        if let Some(latest_password) = passwords.into_iter().next() {
            if let Some(microseconds) = latest_password.expires_at_int
                && let Some(ts) = DateTime::from_timestamp_micros(microseconds)
            {
                self.password_expires_at(ts);
            } else if let Some(expires_at) = latest_password.expires_at {
                self.password_expires_at(expires_at.and_utc());
            }
        }
        self
    }
}

#[cfg(test)]
pub mod tests {
    use chrono::{DateTime, TimeDelta, Utc};

    use crate::entity::password as db_password;

    use super::*;

    /// Create a mock password for testing.
    ///
    /// # Parameters
    /// - `user_id`: The ID of the user.
    ///
    /// # Returns
    /// A `db_password::Model` instance.
    pub fn get_password_mock(user_id: i32) -> db_password::Model {
        let datetime = Utc::now();
        db_password::Model {
            id: user_id,
            local_user_id: user_id,
            self_service: false,
            expires_at: None,
            password_hash: Some("fake_hash".into()),
            created_at: datetime.naive_utc(),
            created_at_int: datetime.naive_utc().and_utc().timestamp_micros(),
            expires_at_int: None,
        }
    }

    impl db_password::ModelBuilder {
        /// Set the password expiration date.
        ///
        /// # Parameters
        /// - `value`: The expiration date.
        ///
        /// # Returns
        /// A mutable reference to the builder.
        pub fn expires(&mut self, value: DateTime<Utc>) -> &mut Self {
            self.expires_at_int(value.timestamp())
                .expires_at(value.naive_utc())
        }

        /// Create an expired password builder.
        ///
        /// # Returns
        /// An expired `Self` builder.
        pub fn expired() -> Self {
            Self::default()
                .expires_at(DateTime::<Utc>::MIN_UTC.naive_utc())
                .expires_at_int(DateTime::<Utc>::MIN_UTC.timestamp())
                .to_owned()
        }

        /// Create a non-expired password builder.
        ///
        /// # Returns
        /// A non-expired `Self` builder.
        pub fn not_expired() -> Self {
            Self::default()
                .expires_at(DateTime::<Utc>::MAX_UTC.naive_utc())
                .expires_at_int(DateTime::<Utc>::MAX_UTC.timestamp())
                .to_owned()
        }

        /// Create a dummy password model.
        ///
        /// # Returns
        /// A `db_password::Model` instance.
        pub fn dummy() -> db_password::Model {
            db_password::ModelBuilder::default().build().unwrap()
        }
    }

    #[test]
    fn test_is_password_expired_not() {
        let now = Utc::now();
        assert!(
            !is_password_expired(&db_password::ModelBuilder::default().build().unwrap()).unwrap(),
            "password with no expiration is not expired"
        );
        assert!(
            !is_password_expired(
                &db_password::ModelBuilder::default()
                    .expires_at_int(
                        now.checked_add_signed(TimeDelta::seconds(5))
                            .unwrap()
                            .timestamp()
                    )
                    .build()
                    .unwrap()
            )
            .unwrap(),
            "password with expires_at_int in the future is not expired"
        );
        assert!(
            !is_password_expired(
                &db_password::ModelBuilder::default()
                    .expires_at(
                        now.checked_add_signed(TimeDelta::seconds(5))
                            .unwrap()
                            .naive_utc()
                    )
                    .build()
                    .unwrap()
            )
            .unwrap(),
            "password with expires_at in the future is not expired"
        );
        assert!(
            !is_password_expired(&db_password::ModelBuilder::not_expired().build().unwrap())
                .unwrap(),
            "password is not expired"
        );
    }

    #[test]
    fn test_is_password_expired_true() {
        let now = Utc::now();
        assert!(
            is_password_expired(
                &db_password::ModelBuilder::default()
                    .expires_at_int(
                        now.checked_sub_signed(TimeDelta::seconds(1))
                            .unwrap()
                            .timestamp()
                    )
                    .build()
                    .unwrap()
            )
            .unwrap(),
            "password with expires_at_int in the past is expired"
        );
        assert!(
            is_password_expired(
                &db_password::ModelBuilder::default()
                    .expires_at(
                        now.checked_sub_signed(TimeDelta::seconds(5))
                            .unwrap()
                            .naive_utc()
                    )
                    .build()
                    .unwrap()
            )
            .unwrap(),
            "password with expires_at in the past is expired"
        );
        assert!(
            is_password_expired(&db_password::ModelBuilder::expired().build().unwrap()).unwrap(),
            "password is expired"
        );
    }
}
