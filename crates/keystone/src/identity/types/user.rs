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

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

use crate::config::Config;
use crate::error::BuilderError;

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserResponse {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their
    /// default project, the default project is ignored at token creation.
    /// Additionally, if your default project is not valid, a token
    /// is issued without an explicit scope of authorization.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub default_project_id: Option<String>,

    /// The ID of the domain.
    #[validate(length(max = 64))]
    pub domain_id: String,
    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    pub enabled: bool,

    /// Additional user properties.
    #[builder(default)]
    pub extra: Option<Value>,

    /// List of federated objects associated with a user. Each object in the
    /// list contains the `idp_id` and `protocols`. `protocols` is a list of
    /// objects, each of which contains `protocol_id` and `unique_id` of the
    /// protocol and user respectively.
    #[builder(default)]
    #[validate(nested)]
    pub federated: Option<Vec<Federation>>,

    /// The user ID.
    #[validate(length(max = 64))]
    pub id: String,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    pub name: String,
    #[builder(default)]

    /// The options for the user.
    #[validate(nested)]
    pub options: UserOptions,

    #[builder(default)]
    pub password_expires_at: Option<DateTime<Utc>>,
}

/// User creation data.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserCreate {
    /// The ID of the default project for the user.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub default_project_id: Option<String>,

    /// The ID of the domain.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// Additional user properties.
    #[builder(default)]
    pub extra: Option<Value>,

    /// List of federated objects associated with a user. Each object in the
    /// list contains the `idp_id` and `protocols`. `protocols` is a list of
    /// objects, each of which contains `protocol_id` and `unique_id` of the
    /// protocol and user respectively.
    #[builder(default)]
    #[validate(nested)]
    pub federated: Option<Vec<Federation>>,

    /// The ID of the user. When unset a new UUID would be assigned.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// The resource options for the user.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<UserOptions>,

    /// User password.
    #[builder(default)]
    #[validate(length(max = 72))]
    pub password: Option<String>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct UserUpdate {
    /// The ID of the default project for the user.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub default_project_id: Option<Option<String>>,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// Additional user properties.
    #[builder(default)]
    pub extra: Option<Value>,

    /// List of federated objects associated with a user. Each object in the
    /// list contains the idp_id and protocols. protocols is a list of objects,
    /// each of which contains protocol_id and unique_id of the protocol and
    /// user respectively.
    #[builder(default)]
    #[validate(nested)]
    pub federated: Option<Vec<Federation>>,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    #[builder(default)]
    pub name: Option<String>,

    /// The resource options for the user.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<UserOptions>,

    /// New user password.
    #[builder(default)]
    #[validate(length(max = 72))]
    pub password: Option<String>,
}

/// User options.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserOptions {
    pub ignore_change_password_upon_first_use: Option<bool>,

    pub ignore_password_expiry: Option<bool>,

    pub ignore_lockout_failure_attempts: Option<bool>,

    pub lock_password: Option<bool>,

    pub ignore_user_inactivity: Option<bool>,

    pub multi_factor_auth_rules: Option<Vec<Vec<String>>>,

    pub multi_factor_auth_enabled: Option<bool>,

    /// Identifies whether the user is a service account.
    pub is_service_account: Option<bool>,
}

/// User federation data.
#[derive(Builder, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Federation {
    /// Identity provider ID.
    #[validate(length(max = 64))]
    pub idp_id: String,

    /// Protocols.
    #[builder(default)]
    #[validate(nested)]
    pub protocols: Vec<FederationProtocol>,

    /// Unique ID of the user within the IdP.
    #[builder]
    pub unique_id: String,
}

/// Federation protocol data.
#[derive(Builder, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct FederationProtocol {
    /// Federation protocol ID.
    #[validate(length(max = 64))]
    pub protocol_id: String,

    // TODO: unique ID should potentially belong to the IDP and not to the protocol
    /// Unique ID of the associated user.
    #[validate(length(max = 64))]
    pub unique_id: String,
}

/// User listing parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
pub struct UserListParameters {
    /// Filter users by the domain.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,

    /// Filter users by the name attribute.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// Filter users by the federated unique ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub unique_id: Option<String>,

    /// Filter users by User Type (local, federated, nonlocal, all).
    #[builder(default)]
    #[serde(default, rename = "type")]
    pub user_type: Option<UserType>,
}

/// User type for filtering.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserType {
    /// All users (default behavior).
    #[default]
    All,

    /// Federated users only (authenticated via external IdP).
    Federated,

    /// Local users only (with passwords).
    Local,

    /// Non-local users (users without local authentication).
    NonLocal,

    /// Service Accounts (bots, etc).
    ServiceAccount,
}

/// User password information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserPasswordAuthRequest {
    /// User ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub id: Option<String>,

    /// User Name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// User domain.
    #[builder(default)]
    #[validate(nested)]
    pub domain: Option<Domain>,

    /// User password expiry date.
    #[builder(default)]
    #[validate(length(max = 72))]
    pub password: String,
}

/// Domain information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Domain {
    /// Domain ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub id: Option<String>,

    /// Domain Name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,
}

/// Calculate the `last_active_at` for the user entry.
pub fn get_user_last_active_at(
    conf: &Config,
    enabled: Option<bool>,
    activity_date: NaiveDateTime,
) -> Option<NaiveDate> {
    if enabled.is_some_and(|x| x) {
        if conf
            .security_compliance
            .disable_user_account_days_inactive
            .is_some()
        {
            Some(activity_date.date())
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_get_user_last_active_at() {
        let now = Utc::now().naive_utc();
        let mut cfg = Config::default();
        assert!(get_user_last_active_at(&cfg, Some(false), now).is_none());
        assert!(get_user_last_active_at(&cfg, Some(true), now).is_none());
        assert!(get_user_last_active_at(&cfg, None, now).is_none());

        cfg.security_compliance.disable_user_account_days_inactive = Some(1);
        assert_eq!(
            get_user_last_active_at(&cfg, Some(true), now),
            Some(now.date())
        );
        assert!(get_user_last_active_at(&cfg, Some(false), now).is_none());
        assert!(get_user_last_active_at(&cfg, None, now).is_none());
    }
}
