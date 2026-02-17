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

use crate::db::entity::password as db_password;
use crate::identity::backend::error::IdentityDatabaseError;
use crate::identity::types::UserResponseBuilder;

mod create;

pub use create::create;

/// Verify whether the password has expired or not.
pub(super) fn is_password_expired(
    password_entry: &db_password::Model,
) -> Result<bool, IdentityDatabaseError> {
    if let Some(expires) = password_entry
        .expires_at_int
        .and_then(DateTime::from_timestamp_secs)
        .or_else(|| password_entry.expires_at.map(|val| val.and_utc()))
    {
        return Ok(expires <= Utc::now());
    }
    Ok(false)
}

impl UserResponseBuilder {
    pub fn merge_passwords_data<I>(&mut self, passwords: I) -> &mut Self
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
pub(crate) mod tests {
    use crate::db::entity::password as db_password;
    use chrono::{DateTime, TimeDelta, Utc};

    use super::*;

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
        pub fn expires(&mut self, value: DateTime<Utc>) -> &mut Self {
            self.expires_at_int(value.timestamp())
                .expires_at(value.naive_utc())
        }

        pub fn expired() -> Self {
            Self::default()
                .expires_at(DateTime::<Utc>::MIN_UTC.naive_utc())
                .expires_at_int(DateTime::<Utc>::MIN_UTC.timestamp())
                .to_owned()
        }

        pub fn not_expired() -> Self {
            Self::default()
                .expires_at(DateTime::<Utc>::MAX_UTC.naive_utc())
                .expires_at_int(DateTime::<Utc>::MAX_UTC.timestamp())
                .to_owned()
        }

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
