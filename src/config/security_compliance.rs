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
use chrono::{NaiveDate, TimeDelta, Utc};
use serde::Deserialize;

use crate::config::common::*;

/// Security compliance configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct SecurityComplianceProvider {
    /// The maximum number of days a user can go without authenticating before
    /// being considered "inactive" and automatically disabled (locked).
    /// This feature is disabled by default; set any value to enable
    /// it. This feature depends on the sql backend for the `[identity] driver`.
    /// When a user exceeds this threshold and is considered "inactive", the
    /// user's enabled attribute in the HTTP API may not match the value of
    /// the user's enabled column in the user table.
    #[serde(default)]
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
    #[serde(default)]
    pub invalid_password_hash_key: Option<String>,
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
    pub invalid_password_hash_max_chars: Option<u8>,

    /// The maximum number of times that a user can fail to authenticate before
    /// the user account is locked for the number of seconds specified by
    /// `[security_compliance] lockout_duration`. This feature is disabled by
    /// default. If this feature is enabled and `[security_compliance]
    /// lockout_duration` is not set, then users may be locked out indefinitely
    /// until the user is explicitly enabled via the API. This feature depends
    /// on the sql backend for the `[identity] driver`.
    #[serde(default)]
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
    pub(crate) fn get_user_last_activity_cutof_date(&self) -> Option<NaiveDate> {
        self.disable_user_account_days_inactive
            .and_then(|inactive_after_days| {
                Utc::now()
                    .checked_sub_signed(TimeDelta::days(inactive_after_days.into()))
                    .map(|val| val.date_naive())
            })
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
