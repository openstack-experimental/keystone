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
use crate::common::*;
use chrono::{DateTime, NaiveDate, TimeDelta, Utc};
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::sync::Arc;
use thiserror::Error;
use validator::Validate;

/// Security compliance configuration errors.
#[derive(Debug, Error)]
pub enum SecurityComplianceError {
    /// Password does not match the configured policy.
    #[error("password does not comply with policy: {0}")]
    PasswordInvalid(String),

    /// The configured password_regex is not a valid regular expression.
    #[error("invalid password_regex configured: {0}")]
    InvalidRegex(regex::Error),
}

/// Security compliance configuration.
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct SecurityComplianceProvider {
    /// The maximum number of days a user can go without authenticating before
    /// being considered "inactive" and automatically disabled (locked).
    /// This feature is disabled by default; set any value to enable
    /// it. This feature depends on the sql backend for the `[identity] driver`.
    /// When a user exceeds this threshold and is considered "inactive", the
    /// user's enabled attribute in the HTTP API may not match the value of
    /// the user's enabled column in the user table.
    #[serde(default)]
    #[validate(range(min = 1))]
    pub disable_user_account_days_inactive: Option<u16>,
    /// Enabling this option requires users to change their password when the
    /// user is created, or upon administrative reset. Before accessing any
    /// services, affected users will have to change their password. To ignore
    /// this requirement for specific users, such as service users, set the
    /// options attribute ignore_change_password_upon_first_use to True for the
    /// desired user via the update user API. This feature is disabled by
    /// default. This feature is only applicable with the sql backend for the
    /// `[identity] driver`.
    #[serde(default)]
    pub change_password_upon_first_use: bool,
    /// If report_invalid_password_hash is configured, defines the hash function
    /// to be used b`y HMAC. Possible values are names suitable to hashlib.new()
    /// <https://docs.python.org/3/library/hashlib.html#hashlib.new>.
    #[serde(default)]
    pub invalid_password_hash_function: InvalidPasswordHashMethod,
    /// If report_invalid_password_hash is configured, uses provided secret key
    /// when generating password hashes to make them unique and distinct from
    /// any other Keystone installations out there. Should be some secret static
    /// value specific to the current installation (the same value should be
    /// used in distributed installations working with the same backend, to make
    /// them all generate equal hashes for equal invalid passwords). 16 bytes
    /// (128 bits) or more is recommended.
    ///
    /// Wrapped in [`SecretString`] to prevent accidental exposure via
    /// Debug/tracing (mirrors `database.connection`).
    #[serde(default)]
    pub invalid_password_hash_key: Option<SecretString>,
    /// This option has a sample default set, which means that its actual
    /// default value may vary from the one documented above.
    ///
    /// If report_invalid_password_hash is configured, defines the number of
    /// characters of hash of invalid password to be returned. When not
    /// specified, returns full hash. Its length depends on implementation and
    /// invalid_password_hash_function configuration, but is typically 16+
    /// characters. It's recommended to use the least reasonable value however -
    /// it's the most effective measure to protect the hashes.
    #[serde(default)]
    #[validate(range(min = 1))]
    pub invalid_password_hash_max_chars: Option<u8>,

    /// The maximum number of times that a user can fail to authenticate before
    /// the user account is locked for the number of seconds specified by
    /// `[security_compliance] lockout_duration`. This feature is disabled by
    /// default. If this feature is enabled and `[security_compliance]
    /// lockout_duration` is not set, then users may be locked out indefinitely
    /// until the user is explicitly enabled via the API. This feature depends
    /// on the sql backend for the `[identity] driver`.
    #[serde(default)]
    #[validate(range(min = 1))]
    pub lockout_failure_attempts: Option<u16>,
    /// The number of seconds a user account will be locked when the maximum
    /// number of failed authentication attempts (as specified by
    /// `[security_compliance] lockout_failure_attempts`) is exceeded. Setting
    /// this option will have no effect unless you also set
    /// `[security_compliance] lockout_failure_attempts` to a non-zero value.
    /// This feature depends on the sql backend for the `[identity]` driver.
    #[serde(
        deserialize_with = "optional_timedelta_from_seconds",
        default = "AccountLockoutDuration::default"
    )]
    pub lockout_duration: Option<TimeDelta>,
    /// The number of days that a password must be used before the user can
    /// change it. This prevents users from changing their passwords immediately
    /// in order to wipe out their password history and reuse an old password.
    /// This feature does not prevent administrators from manually resetting
    /// passwords. It is disabled by default and allows for immediate password
    /// changes. This feature depends on the sql backend for the `[identity]
    /// driver` driver. Note: If `[security_compliance] password_expires_days`
    /// is set, then the value for this option should be less than the
    /// `password_expires_days`.
    #[serde(default)]
    pub minimum_password_age: u32,
    /// The number of days for which a password will be considered valid before
    /// requiring it to be changed. This feature is disabled by default. If
    /// enabled, new password changes will have an expiration date,
    /// however existing passwords would not be impacted. This feature depends
    /// on the sql backend for the `[identity] driver`.
    #[serde(default)]
    #[validate(range(min = 1))]
    pub password_expires_days: Option<u64>,
    /// The regular expression used to validate password strength requirements.
    /// By default, the regular expression will match any password. The
    /// following is an example of a pattern which requires at least 1 letter, 1
    /// digit, and have a minimum length of 7 characters:
    /// ^(?=.*\d)(?=.*[a-zA-Z]).{7,}$ This feature depends on the sql backend
    /// for the `[identity] driver`.
    #[serde(default)]
    pub password_regex: Option<String>,
    /// Describe your password regular expression here in language for humans.
    /// If a password fails to match the regular expression, the contents of
    /// this configuration variable will be returned to users to explain why
    /// their requested password was insufficient.
    #[serde(default)]
    pub password_regex_description: Option<String>,

    /// Pre-compiled regex from `password_regex`, initialized at config load
    /// time.
    #[serde(skip)]
    pub password_regex_re: Option<Arc<Regex>>,
    /// This option has a sample default set, which means that its actual
    /// default value may vary from the one documented above.
    ///
    /// When configured, enriches the corresponding output channel with hash of
    /// invalid password, which could be further used to distinguish bruteforce
    /// attacks from e.g. external user automations that did not timely update
    /// rotated password by analyzing variability of the hash value. Additional
    /// configuration parameters are available using other
    /// invalid_password_hash_* configuration entries, that only take effect
    /// when this option is activated.
    #[serde(default = "ReportInvalidPasswordHash::default")]
    pub report_invalid_password_hash: Vec<InvalidPasswordHashReport>,
    /// This controls the number of previous user password iterations to keep in
    /// history, in order to enforce that newly created passwords are unique.
    /// The total number which includes the new password should not be greater
    /// or equal to this value. Setting the value to zero (the default) disables
    /// this feature. Thus, to enable this feature, values must be greater than
    /// 0. This feature depends on the sql backend for the `[identity]` driver.
    #[serde(default)]
    pub unique_last_password_count: Option<u16>,
}

impl Default for SecurityComplianceProvider {
    fn default() -> Self {
        Self {
            disable_user_account_days_inactive: None,
            change_password_upon_first_use: false,
            invalid_password_hash_function: InvalidPasswordHashMethod::default(),
            invalid_password_hash_key: None,
            invalid_password_hash_max_chars: None,
            lockout_failure_attempts: None,
            lockout_duration: AccountLockoutDuration::default(),
            minimum_password_age: 0,
            password_expires_days: None,
            password_regex: None,
            password_regex_description: None,
            password_regex_re: None,
            report_invalid_password_hash: ReportInvalidPasswordHash::default(),
            unique_last_password_count: None,
        }
    }
}

impl SecurityComplianceProvider {
    /// Return oldest last_active_at date for the user to be considered active.
    ///
    /// When [`disable_user_account_days_inactive`](field@
    /// SecurityComplianceProvider::disable_user_account_days_inactive)
    /// is set return the corresponding oldest user activity date for it to be
    /// considered as disabled. When the option is not set returns `None`.
    pub fn get_user_last_activity_cutof_date(&self) -> Option<NaiveDate> {
        self.disable_user_account_days_inactive
            .and_then(|inactive_after_days| {
                Utc::now()
                    .checked_sub_signed(TimeDelta::days(inactive_after_days.into()))
                    .map(|val| val.date_naive())
            })
    }

    /// Calculate password expiration time.
    ///
    /// # Parameters
    /// - `now`: The current time.
    ///
    /// # Returns
    /// An `Option` with the expiration date, or `None` if password expiration
    /// is not configured.
    pub fn get_password_expires_at(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.password_expires_days
            .map(|days| now + chrono::TimeDelta::days(days as i64))
    }

    /// Compile the configured `password_regex` once at config load time.
    ///
    /// Must be called after the struct is deserialized. Returns an error if the
    /// configured regex string is not valid.
    pub fn compile_regex(&mut self) -> Result<(), SecurityComplianceError> {
        if let Some(ref s) = self.password_regex {
            let re = Regex::new(s).map_err(SecurityComplianceError::InvalidRegex)?;
            self.password_regex_re = Some(Arc::new(re));
        }
        Ok(())
    }

    /// Validate a password against the security-compliance policy.
    ///
    /// An empty password is **always** rejected, regardless of configuration —
    /// this is the central guard for every write path (create/update/change),
    /// and replaces the per-DTO `length(min = 1)` check that could not be kept on
    /// the wrapped [`SecretString`] fields (validator's `custom`/`length` require
    /// the field to be `Serialize`, which secrets deliberately are not).
    ///
    /// Beyond that, returns `Ok(())` when the password matches the configured
    /// regex pattern (or when no pattern is configured), otherwise
    /// `Err(SecurityComplianceError::PasswordInvalid)` with the human-readable
    /// policy description.
    pub fn validate_password(
        &self,
        password: &SecretString,
    ) -> Result<(), SecurityComplianceError> {
        if password.expose_secret().is_empty() {
            return Err(SecurityComplianceError::PasswordInvalid(
                "password must not be empty".to_string(),
            ));
        }
        if let Some(ref re) = self.password_regex_re
            && !re.is_match(password.expose_secret())
        {
            let description = self.password_regex_description.clone().unwrap_or_else(|| {
                "password does not comply with the configured security policy".to_string()
            });
            return Err(SecurityComplianceError::PasswordInvalid(description));
        }
        Ok(())
    }
}

struct AccountLockoutDuration {}
impl AccountLockoutDuration {
    fn default() -> Option<TimeDelta> {
        Some(TimeDelta::seconds(1800))
    }
}

struct ReportInvalidPasswordHash {}
impl ReportInvalidPasswordHash {
    fn default() -> Vec<InvalidPasswordHashReport> {
        vec![InvalidPasswordHashReport::Event]
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub enum InvalidPasswordHashReport {
    #[default]
    Event,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub enum InvalidPasswordHashMethod {
    #[default]
    Sha256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_regex_success() {
        let mut sc = SecurityComplianceProvider {
            password_regex: Some(r"^.{3,}$".to_string()),
            ..Default::default()
        };
        assert!(sc.compile_regex().is_ok());
        assert!(sc.password_regex_re.is_some());
    }

    #[test]
    fn test_compile_regex_invalid() {
        let mut sc = SecurityComplianceProvider {
            password_regex: Some("[invalid_regex".to_string()),
            ..Default::default()
        };
        let result = sc.compile_regex();
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(SecurityComplianceError::InvalidRegex(_))
        ));
    }

    #[test]
    fn test_compile_regex_none() {
        let mut sc = SecurityComplianceProvider::default();
        assert!(sc.compile_regex().is_ok());
        assert!(sc.password_regex_re.is_none());
    }

    #[test]
    fn test_validate_password_matches() {
        let mut sc = SecurityComplianceProvider {
            password_regex: Some(r"^.{3,}$".to_string()),
            ..Default::default()
        };
        sc.compile_regex().unwrap();

        assert!(sc.validate_password(&SecretString::from("Abc1")).is_ok());
    }

    #[test]
    fn test_validate_password_fails_with_description() {
        let mut sc = SecurityComplianceProvider {
            password_regex: Some(r"^.{7,}$".to_string()),
            password_regex_description: Some("must be at least 7 characters long".to_string()),
            ..Default::default()
        };
        sc.compile_regex().unwrap();

        let result = sc.validate_password(&SecretString::from("short"));
        assert!(result.is_err());
        match result {
            Err(SecurityComplianceError::PasswordInvalid(msg)) => {
                assert!(msg.contains("must be at least 7 characters"));
            }
            other => panic!("expected PasswordInvalid, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_password_fails_without_description() {
        let mut sc = SecurityComplianceProvider {
            password_regex: Some(r"^.{10,}$".to_string()),
            ..Default::default()
        };
        sc.compile_regex().unwrap();

        let result = sc.validate_password(&SecretString::from("short"));
        assert!(result.is_err());
        match result {
            Err(SecurityComplianceError::PasswordInvalid(msg)) => {
                assert!(msg.contains("configured security policy"));
            }
            other => panic!("expected PasswordInvalid, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_password_no_regex_always_passes() {
        let sc = SecurityComplianceProvider::default();
        assert!(sc.validate_password(&SecretString::from("a")).is_ok());
    }

    #[test]
    fn test_validate_password_empty_string_fails() {
        let mut sc = SecurityComplianceProvider {
            password_regex: Some(r"^.{1,}$".to_string()),
            ..Default::default()
        };
        sc.compile_regex().unwrap();

        let result = sc.validate_password(&SecretString::from(""));
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(SecurityComplianceError::PasswordInvalid(_))
        ));
    }

    #[test]
    fn test_validate_password_complex_regex() {
        let mut sc = SecurityComplianceProvider {
            // Require: digit, letter, min 3 chars (using concatenation, not lookahead)
            password_regex: Some(r"^.*[a-zA-Z].*[0-9].*$".to_string()),
            ..Default::default()
        };
        sc.compile_regex().unwrap();

        assert!(sc.validate_password(&SecretString::from("Abc1")).is_ok());
        assert!(
            sc.validate_password(&SecretString::from("allletters"))
                .is_err()
        );
        assert!(
            sc.validate_password(&SecretString::from("12345678"))
                .is_err()
        );
    }

    #[test]
    fn test_load_all_compiles_regex() {
        let mut cfg = SecurityComplianceProvider::default();
        // Default has no regex, so compile_regex is a no-op
        assert!(cfg.compile_regex().is_ok());
        assert!(cfg.password_regex_re.is_none());
    }

    /// Regression guard for #369: wrapping the password in `SecretString` meant
    /// the per-DTO `length(min = 1)` guard could not be kept (validator's
    /// `custom` needs the field to be `Serialize`). The non-empty check moved
    /// here and MUST reject an empty password even when no regex is configured.
    #[test]
    fn validate_password_rejects_empty_without_regex() {
        let sc = SecurityComplianceProvider::default();
        assert!(sc.password_regex_re.is_none(), "precondition: no regex");
        let result = sc.validate_password(&SecretString::from(""));
        assert!(
            matches!(result, Err(SecurityComplianceError::PasswordInvalid(_))),
            "empty password must be rejected without a regex, got {result:?}"
        );
        // A non-empty password still passes when no policy is configured.
        assert!(sc.validate_password(&SecretString::from("x")).is_ok());
    }

    /// The `invalid_password_hash_key` secret must never render under `Debug`
    /// (Sea-ORM/tracing could otherwise log the whole config section).
    #[test]
    fn invalid_password_hash_key_redacts_under_debug() {
        let sc = SecurityComplianceProvider {
            invalid_password_hash_key: Some(SecretString::from("HASHKEYLEAK")),
            ..Default::default()
        };
        assert!(
            !format!("{sc:?}").contains("HASHKEYLEAK"),
            "invalid_password_hash_key leaked via Debug"
        );
    }
}
