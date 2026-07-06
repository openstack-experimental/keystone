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

//! # Identity provider
//!
//! Following identity concepts are covered by the identity provider:
//!
//! ## Group
//!
//! An Identity service API v3 entity. Groups are a collection of users
//! owned by a domain. A group role, granted to a domain or project, applies to
//! all users in the group. Adding or removing users to or from a group grants
//! or revokes their role and authentication to the associated domain or
//! project.
//!
//! ## User
//!
//! A digital representation of a person, system, or service that uses
//! OpenStack cloud services. The Identity service validates that incoming
//! requests are made by the user who claims to be making the call. Users have a
//! login and can access resources by using assigned tokens. Users can be
//! directly assigned to a particular project and behave as if they are
//! contained in that project.

use chrono::{NaiveDate, NaiveDateTime};

use openstack_keystone_config::Config;

pub mod backend;
pub mod error;
pub mod hook;
mod provider_api;
pub mod service;
pub mod shadow_id;

pub use error::IdentityProviderError;
pub use hook::IdentityHook;
pub use provider_api::IdentityApi;
pub use service::IdentityService;
pub use shadow_id::generate_public_id;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockIdentityProvider;

/// Calculate the `last_active_at` for the user entry.
///
/// # Parameters
/// - `conf`: The service configuration.
/// - `enabled`: Whether the user is enabled.
/// - `activity_date`: The date of last activity.
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
    use chrono::Utc;

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
