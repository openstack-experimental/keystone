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

//! # OpenStack Keystone API types
//!
//! This crates defines reusable types that OpenStack Keystone is using for
//! the REST API.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub mod catalog;
#[cfg(feature = "conv")]
mod catalog_conv;
pub mod error;
#[cfg(feature = "conv")]
mod error_conv;
pub mod federation;
pub mod k8s_auth;
pub mod scope;
#[cfg(feature = "conv")]
mod scope_conv;
pub mod trust;
pub mod v3;
pub mod v4;
pub mod version;
pub mod webauthn;

/// Link object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Link {
    /// Link rel attribute.
    #[cfg_attr(feature = "validate", validate(length(max = 10)))]
    pub rel: String,
    /// link href attribute.
    #[cfg_attr(feature = "validate", validate(url))]
    pub href: String,
}

impl Link {
    pub fn new(href: String) -> Self {
        Self {
            rel: "self".into(),
            href,
        }
    }
}

/// Return `true` to be used as a positive default for the serde macros.
pub fn default_true() -> bool {
    true
}

fn deserialize_optional_flatten_value<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let val: Value = Value::deserialize(deserializer)?;
    if val.as_object().is_some_and(|x| x.is_empty()) {
        Ok(None)
    } else {
        Ok(Some(val))
    }
}
