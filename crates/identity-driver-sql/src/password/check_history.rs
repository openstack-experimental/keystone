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

use secrecy::SecretString;

use openstack_keystone_config::Config;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::password as db_password;

/// Check if a new password matches any password in the history.
///
/// Compares the new password against the most recent
/// `unique_last_password_count` password hashes. Returns an error if the new
/// password matches any hash in the history window.
///
/// # Parameters
/// - `conf`: The service configuration.
/// - `passwords`: Existing passwords sorted by creation date (descending).
/// - `new_password`: The new password to check.
///
/// # Returns
/// A `Result` containing `()` if the new password is not in the history, or an
/// `Error` if it matches any password in the history window.
pub async fn check_password_history<'a, I>(
    conf: &Config,
    passwords: I,
    new_password: &SecretString,
) -> Result<(), IdentityProviderError>
where
    I: IntoIterator<Item = &'a db_password::Model>,
{
    let unique_count = conf
        .security_compliance
        .unique_last_password_count
        .unwrap_or(0);

    if unique_count > 0 {
        let check_count = unique_count as usize;
        for (i, check_password) in passwords.into_iter().enumerate() {
            if i >= check_count {
                break;
            }
            if let Some(ref check_hash) = check_password.password_hash
                && openstack_keystone_password_hashing::verify_password(
                    conf,
                    new_password,
                    check_hash,
                )
                .await
                .is_ok_and(|x| x)
            {
                return Err(IdentityProviderError::SecurityCompliance(
                    openstack_keystone_config::SecurityComplianceError::PasswordInvalid(
                        "new password matches a previous password in history".to_string(),
                    ),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::password as db_password;
    use chrono::Utc;

    fn make_password_hash_mock(hash: &str) -> db_password::Model {
        let now = Utc::now();
        db_password::Model {
            id: 1,
            local_user_id: 1,
            self_service: false,
            expires_at: None,
            password_hash: Some(hash.to_string()),
            created_at: now.naive_utc(),
            created_at_int: now.timestamp_micros(),
            expires_at_int: None,
        }
    }

    fn make_password_hash_mock_empty() -> db_password::Model {
        let now = Utc::now();
        db_password::Model {
            id: 1,
            local_user_id: 1,
            self_service: false,
            expires_at: None,
            password_hash: None,
            created_at: now.naive_utc(),
            created_at_int: now.timestamp_micros(),
            expires_at_int: None,
        }
    }

    fn get_config_none_hashing() -> Config {
        let mut config = Config::default();
        config.identity.password_hashing_algorithm =
            openstack_keystone_config::PasswordHashingAlgo::None;
        config
    }

    fn get_config_none_hashing_with_history(count: u16) -> Config {
        let mut config = get_config_none_hashing();
        config.security_compliance.unique_last_password_count = Some(count);
        config
    }

    #[tokio::test]
    async fn test_check_password_history_disabled_allows_any() {
        let config = get_config_none_hashing();
        let passwords = vec![
            make_password_hash_mock("same_password"),
            make_password_hash_mock("other_password"),
        ];

        let result =
            check_password_history(&config, &passwords, &SecretString::from("same_password")).await;
        assert!(
            result.is_ok(),
            "history disabled (unique=0), should allow any"
        );
    }

    #[tokio::test]
    async fn test_check_password_history_reuse_rejected() {
        let config = get_config_none_hashing_with_history(2);
        let passwords = vec![
            make_password_hash_mock("current_password"),
            make_password_hash_mock("old_password_1"),
        ];

        let result =
            check_password_history(&config, &passwords, &SecretString::from("old_password_1"))
                .await;
        assert!(
            matches!(result, Err(IdentityProviderError::SecurityCompliance(_))),
            "reusing a password from history should be rejected"
        );
    }

    #[tokio::test]
    async fn test_check_password_history_rejected_only_within_count() {
        let config = get_config_none_hashing_with_history(1);
        let passwords = vec![
            make_password_hash_mock("current_password"),
            make_password_hash_mock("old_password_1"),
            make_password_hash_mock("old_password_2"),
        ];

        // old_password_2 is beyond history count (unique=1), should be allowed
        let result =
            check_password_history(&config, &passwords, &SecretString::from("old_password_2"))
                .await;
        assert!(
            result.is_ok(),
            "old_password_2 is beyond history count (unique=1), should be allowed"
        );
    }

    #[tokio::test]
    async fn test_check_password_history_empty_hash_allowed() {
        let config = get_config_none_hashing_with_history(2);
        let passwords = vec![
            make_password_hash_mock("current_password"),
            make_password_hash_mock_empty(),
        ];

        let result =
            check_password_history(&config, &passwords, &SecretString::from("some_password")).await;
        assert!(result.is_ok(), "empty hash should be skipped");
    }

    #[tokio::test]
    async fn test_check_password_history_no_match_allowed() {
        let config = get_config_none_hashing_with_history(3);
        let passwords = vec![
            make_password_hash_mock("old_password_1"),
            make_password_hash_mock("old_password_2"),
            make_password_hash_mock("old_password_3"),
        ];

        let result = check_password_history(
            &config,
            &passwords,
            &SecretString::from("brand_new_password"),
        )
        .await;
        assert!(
            result.is_ok(),
            "new password should be allowed, {:?}",
            result
        );
    }
}
