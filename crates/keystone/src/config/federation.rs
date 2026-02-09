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
use chrono::{DateTime, TimeDelta, Utc};
use serde::Deserialize;

use crate::config::common::default_sql_driver;

/// Federation provider.
#[derive(Debug, Deserialize, Clone)]
pub struct FederationProvider {
    /// Federation provider backend.
    #[serde(default = "default_sql_driver")]
    pub driver: String,
    /// Default time in minutes for the validity of group memberships carried
    /// over from a mapping. Default is 0, which means disabled.
    #[serde(default)]
    pub default_authorization_ttl: u32,
}

impl Default for FederationProvider {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
            default_authorization_ttl: 0,
        }
    }
}

impl FederationProvider {
    /// Return oldest `last_verified` date for the expiring user group
    /// membership.
    ///
    /// Calculate the oldest time for the expiring user group membership to not
    /// be considered as valid.
    pub(crate) fn get_expiring_user_group_membership_cutof_datetime(&self) -> DateTime<Utc> {
        Utc::now()
            .checked_sub_signed(TimeDelta::seconds(self.default_authorization_ttl.into()))
            .unwrap_or(Utc::now())
    }
}
