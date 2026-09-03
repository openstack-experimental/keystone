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
//! Domain configuration API types conversions.

use serde_json::{Map, Value};

use openstack_keystone_core_types::domain_config as core;

use crate::v3::domain_config as api_types;

/// Serialize a value that only ever holds JSON objects and scalars, falling
/// back to an empty object on the impossible serialization failure (avoids
/// `unwrap` while keeping the conversions infallible).
fn to_object(value: impl serde::Serialize) -> Value {
    serde_json::to_value(value).unwrap_or_else(|_| Value::Object(Map::new()))
}

impl From<core::DomainConfig> for api_types::DomainConfigResponse {
    fn from(value: core::DomainConfig) -> Self {
        // `DomainConfig`'s `Serialize` already drops sensitive options.
        Self {
            config: to_object(&value),
        }
    }
}

impl From<core::DomainConfigGroup> for api_types::DomainConfigResponse {
    fn from(value: core::DomainConfigGroup) -> Self {
        let mut config = Map::new();
        config.insert(value.name().to_string(), to_object(&value));
        Self {
            config: Value::Object(config),
        }
    }
}

impl From<core::DomainConfigOption> for api_types::DomainConfigResponse {
    fn from(value: core::DomainConfigOption) -> Self {
        let mut options = Map::new();
        options.insert(value.option.clone(), value.value.as_value().clone());
        let mut config = Map::new();
        config.insert(value.group.to_string(), Value::Object(options));
        Self {
            config: Value::Object(config),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use openstack_keystone_core_types::domain_config::{
        DomainConfig, DomainConfigGroupName, DomainConfigOption,
    };

    use super::*;

    #[test]
    fn whole_config_response_drops_sensitive_options() {
        let config = DomainConfig::from_value(json!({
            "ldap": {"url": "ldap://example", "password": "s3cr3t"}
        }))
        .expect("valid config");

        let response = api_types::DomainConfigResponse::from(config);

        assert_eq!(response.config["ldap"]["url"], json!("ldap://example"));
        assert!(response.config["ldap"].get("password").is_none());
    }

    #[test]
    fn group_response_is_wrapped_under_the_group_name() {
        let group = DomainConfig::from_value(json!({"ldap": {"url": "ldap://example"}}))
            .expect("valid config")
            .into_group(DomainConfigGroupName::Ldap)
            .expect("ldap group");

        let response = api_types::DomainConfigResponse::from(group);

        assert_eq!(response.config, json!({"ldap": {"url": "ldap://example"}}));
    }

    #[test]
    fn option_response_is_wrapped_under_group_and_option() {
        let option = DomainConfigOption::new(DomainConfigGroupName::Identity, "driver", "sql");

        let response = api_types::DomainConfigResponse::from(option);

        assert_eq!(response.config, json!({"identity": {"driver": "sql"}}));
    }
}
