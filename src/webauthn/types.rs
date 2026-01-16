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

//! # WebAuthN Extension types

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::fmt;
use validator::Validate;
use webauthn_rs::prelude::Passkey;

mod provider;

pub use provider::WebauthnApi;

/// WebAuthN credential of a user.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(strip_option, into))]
pub struct WebauthnCredential {
    /// Usage counter.
    pub counter: u32,

    /// Credential registration date.
    pub created_at: DateTime<Utc>,

    /// The ID of the credential.
    #[validate(length(min = 1, max = 1024))]
    pub credential_id: String,

    /// Internal credential data.
    pub data: Passkey,

    /// The description of the credential.
    #[validate(length(min = 1, max = 64))]
    pub description: Option<String>,

    /// Internal ID of the credential.
    pub internal_id: i32,

    /// Last used date.
    pub last_used_at: Option<DateTime<Utc>>,

    /// Credential type.
    pub r#type: CredentialType,

    /// Update date.
    pub updated_at: Option<DateTime<Utc>>,

    /// User ID.
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,
}

/// WebauthN credential type.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CredentialType {
    /// Cross-platform credential.
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CredentialType::CrossPlatform => write!(f, "cross-platform"),
        }
    }
}

impl From<&str> for CredentialType {
    fn from(val: &str) -> CredentialType {
        match val {
            "cross-platform" => Self::CrossPlatform,
            _ => Self::CrossPlatform,
        }
    }
}

impl From<String> for CredentialType {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}
