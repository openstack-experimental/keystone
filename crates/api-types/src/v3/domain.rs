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
//! # Domain API types.

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// Short domain representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct DomainShort {
    /// If set to true, domain is enabled. If set to false, domain is disabled.
    pub enabled: bool,

    /// The domain ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// The domain name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,
}

/// Full domain representation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Domain {
    /// The description of the domain.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub description: Option<String>,

    /// If set to true, domain is enabled. If set to false, domain is disabled.
    pub enabled: bool,

    /// Additional domain properties.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,

    /// The domain ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// The domain name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,
}

/// New domain data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct DomainCreate {
    /// The description of the domain.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// If set to true, domain is enabled. If set to false, domain is disabled.
    #[cfg_attr(feature = "builder", builder(default = "crate::default_true()"))]
    pub enabled: bool,

    /// Additional domain properties.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,

    /// The domain ID.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The domain name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,
}

/// Complete response with the domain data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct DomainResponse {
    /// Domain object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domain: Domain,
}

/// New domain creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct DomainCreateRequest {
    /// Domain object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domain: DomainCreate,
}

/// List of domains.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct DomainList {
    /// Collection of domain objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domains: Vec<Domain>,
}

/// Domain list parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct DomainListParameters {
    /// Filter domains by the `id` attribute.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub ids: Option<String>,

    /// Filter domains by the `name` attribute.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "builder")]
    use super::*;

    #[cfg(feature = "builder")]
    #[test]
    fn test_domain_create() {
        let sot = DomainCreateBuilder::default().name("name").build().unwrap();
        assert!(sot.enabled, "enabled defaults to true");
        assert!(sot.id.is_none());
    }

    #[cfg(feature = "builder")]
    #[test]
    fn test_domain_serialize_extra() {
        assert_eq!(
            serde_json::json!({"name": "name", "enabled": true}),
            serde_json::to_value(DomainCreateBuilder::default().name("name").build().unwrap())
                .unwrap()
        );
        assert_eq!(
            serde_json::json!({"name": "name", "enabled": true, "unknown": "bar"}),
            serde_json::to_value(
                DomainCreateBuilder::default()
                    .name("name")
                    .extra(std::collections::HashMap::from([(
                        "unknown".into(),
                        serde_json::json!("bar")
                    )]))
                    .build()
                    .unwrap()
            )
            .unwrap()
        );
    }
}
