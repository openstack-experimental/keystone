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
use serde::Deserialize;

use crate::common::default_sql_driver;
use crate::pagination::ListLimitConfig;

/// Unified limits provider.
#[derive(Debug, Deserialize, Clone)]
pub struct LimitProvider {
    /// Limit provider driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// The enforcement model used to validate limits.
    #[serde(default)]
    pub enforcement_model: LimitEnforcementModel,

    /// `GET /v3/registered_limits` and `/v3/limits` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,
}

/// Limit enforcement model.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LimitEnforcementModel {
    /// Project hierarchy is not taken into account.
    #[default]
    Flat,
    /// Project hierarchy must not exceed the depth of two (domain, project).
    StrictTwoLevel,
}

impl Default for LimitProvider {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
            enforcement_model: LimitEnforcementModel::default(),
            list_limit: ListLimitConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_deserialize() {
        let cfg: LimitProvider =
            serde_json::from_str(r#"{"enforcement_model": "strict_two_level"}"#).unwrap();
        assert_eq!(LimitEnforcementModel::StrictTwoLevel, cfg.enforcement_model);
        assert_eq!("sql", cfg.driver);
        assert_eq!(
            LimitEnforcementModel::Flat,
            LimitProvider::default().enforcement_model
        );
    }
}
