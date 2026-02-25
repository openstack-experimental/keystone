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

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

pub mod catalog;
pub mod error;
pub mod federation;
pub mod k8s_auth;
pub mod scope;
pub mod trust;
pub mod v3;
pub mod v4;
pub mod version;
pub mod webauthn;

/// Link object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Link {
    /// Link rel attribute.
    #[validate(length(max = 10))]
    pub rel: String,
    /// link href attribute.
    #[validate(url)]
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
