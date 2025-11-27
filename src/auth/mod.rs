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

//! Authorization and authentication information.
//!
//! Authentication and authorization types with corresponding validation.
//! Authentication specific validation may stay in the corresponding provider
//! (i.e. user password is expired), but general validation rules must be
//! present here to be shared across different authentication methods. The
//! same is valid for the authorization validation (project/domain must exist
//! and be enabled).

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::identity::types::{Group, UserResponse};
use crate::resource::types::{Domain, Project};

#[derive(Error, Debug)]
pub enum AuthenticationError {
    /// Builder error
    #[error("building authentication information: {source}")]
    AuthenticatedInfoBuilder {
        #[from]
        source: AuthenticatedInfoBuilderError,
    },

    /// Unauthorized
    #[error("The request you have made requires authentication.")]
    Unauthorized,

    /// User is disabled
    #[error("The account is disabled for user: {0}")]
    UserDisabled(String),

    /// User is locked due to the multiple failed attempts.
    #[error("The account is temporarily disabled for user: {0}")]
    UserLocked(String),

    /// User password is expired.
    #[error("The password is expired for user: {0}")]
    UserPasswordExpired(String),

    #[error("wrong username or password")]
    UserNameOrPasswordWrong,

    /// Token renewal is forbidden
    #[error("Token renewal (getting token from token) is prohibited.")]
    TokenRenewalForbidden,
}

/// Information about successful authentication
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(into, strip_option))]
pub struct AuthenticatedInfo {
    /// User id.
    pub user_id: String,

    /// Resolved user object.
    #[builder(default)]
    pub user: Option<UserResponse>,

    /// Resolved user domain information.
    #[builder(default)]
    pub user_domain: Option<Domain>,

    /// Resolved user object.
    #[builder(default)]
    pub user_groups: Vec<Group>,

    /// Authentication methods.
    #[builder(default)]
    pub methods: Vec<String>,

    /// Audit IDs.
    #[builder(default)]
    pub audit_ids: Vec<String>,

    /// Federated IDP id.
    #[builder(default)]
    pub idp_id: Option<String>,

    /// Federated protocol id.
    #[builder(default)]
    pub protocol_id: Option<String>,

    /// Token restriction.
    #[builder(default)]
    pub token_restriction_id: Option<String>,
}

impl AuthenticatedInfo {
    pub fn builder() -> AuthenticatedInfoBuilder {
        AuthenticatedInfoBuilder::default()
    }

    /// Validate the authentication information
    ///
    /// - User attribute must be set
    /// - User must be enabled
    /// - User object id must match user_id
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        // TODO: all validations (disabled user, locked, etc) should be placed here
        // since every authentication method goes different way and we risk
        // missing validations
        if let Some(user) = &self.user {
            if user.id != self.user_id {
                warn!(
                    "User data does not match the user_id attribute: {} vs {}",
                    self.user_id, user.id
                );
                return Err(AuthenticationError::Unauthorized);
            }
            if !user.enabled {
                return Err(AuthenticationError::UserDisabled(self.user_id.clone()));
            }
        } else {
            warn!(
                "User data must be resolved in the AuthenticatedInfo before validating: {:?}",
                self
            );
            return Err(AuthenticationError::Unauthorized);
        }

        Ok(())
    }
}

/// Authorization information
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum AuthzInfo {
    /// Unscoped
    Unscoped,
    /// Project scope
    Project(Project),
    /// Domain scope
    Domain(Domain),
}

impl AuthzInfo {
    /// Validate the authorization information
    ///
    /// - Unscoped: always valid
    /// - Project: check if the project is enabled
    /// - Domain: check if the domain is enabled
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        match self {
            AuthzInfo::Unscoped => {}
            AuthzInfo::Project(project) => {
                if !project.enabled {
                    return Err(AuthenticationError::Unauthorized);
                }
            }
            AuthzInfo::Domain(domain) => {
                if !domain.enabled {
                    return Err(AuthenticationError::Unauthorized);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tracing_test::traced_test;

    use crate::identity::types::UserResponse;

    #[test]
    fn test_authn_validate_no_user() {
        let authn = AuthenticatedInfo::builder().user_id("uid").build().unwrap();
        if let Err(AuthenticationError::Unauthorized) = authn.validate() {
        } else {
            panic!("should be unauthorized");
        }
    }

    #[test]
    #[traced_test]
    fn test_authn_validate_user_disabled() {
        let authn = AuthenticatedInfo::builder()
            .user_id("uid")
            .user(UserResponse {
                id: "uid".to_string(),
                enabled: false,
                ..Default::default()
            })
            .build()
            .unwrap();
        if let Err(AuthenticationError::UserDisabled(uid)) = authn.validate() {
            assert_eq!("uid", uid);
        } else {
            panic!("should fail for disabled user");
        }
    }

    #[test]
    #[traced_test]
    fn test_authn_validate_user_mismatch() {
        let authn = AuthenticatedInfo::builder()
            .user_id("uid1")
            .user(UserResponse {
                id: "uid2".to_string(),
                enabled: false,
                ..Default::default()
            })
            .build()
            .unwrap();
        if let Err(AuthenticationError::Unauthorized) = authn.validate() {
        } else {
            panic!("should fail when user_id != user.id");
        }
    }

    #[test]
    #[traced_test]
    fn test_authz_validate_project() {
        let authz = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        assert!(authz.validate().is_ok());
    }

    #[test]
    #[traced_test]
    fn test_authz_validate_project_disabled() {
        let authz = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: false,
            ..Default::default()
        });
        if let Err(AuthenticationError::Unauthorized) = authz.validate() {
        } else {
            panic!("should fail when project is not enabled");
        }
    }

    #[test]
    #[traced_test]
    fn test_authz_validate_domain() {
        let authz = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        assert!(authz.validate().is_ok());
    }

    #[test]
    #[traced_test]
    fn test_authz_validate_domain_disabled() {
        let authz = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: false,
            ..Default::default()
        });
        if let Err(AuthenticationError::Unauthorized) = authz.validate() {
        } else {
            panic!("should fail when domain is not enabled");
        }
    }

    #[test]
    #[traced_test]
    fn test_authz_validate_unscoped() {
        let authz = AuthzInfo::Unscoped;
        assert!(authz.validate().is_ok());
    }
}
