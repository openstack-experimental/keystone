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
//! # Application credential access rule

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use validator::Validate;

/// The application credential access rule object.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(strip_option, into))]
pub struct AccessRule {
    /// The ID of the access rule.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The request method that the application credential is permitted to use
    /// for a given API endpoint.
    #[builder(default)]
    #[validate(length(min = 1, max = 16))]
    pub method: Option<String>,

    /// The API path that the application credential is permitted to access.
    /// May use named wildcards such as {tag} or the unnamed wildcard `*` to
    /// match against any string in the path up to a `/`, or the recursive
    /// wildcard `**` to include `/` in the matched path.
    #[builder(default)]
    #[validate(length(min = 1, max = 128))]
    pub path: Option<String>,

    /// The service type identifier for the service that the application
    /// credential is permitted to access. Must be a service type that is
    /// listed in the service catalog and not a code name for a service.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub service: Option<String>,
    // TODO: modify DB so that user_id is not nullable
}

/// The application credential access rule object to be created.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(strip_option, into))]
pub struct AccessRuleCreate {
    /// The ID of the access rule.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The request method that the application credential is permitted to use
    /// for a given API endpoint.
    #[builder(default)]
    #[validate(length(min = 1, max = 16))]
    pub method: Option<String>,

    /// The API path that the application credential is permitted to access.
    /// May use named wildcards such as {tag} or the unnamed wildcard `*` to
    /// match against any string in the path up to a `/`, or the recursive
    /// wildcard `**` to include `/` in the matched path.
    #[builder(default)]
    #[validate(length(min = 1, max = 128))]
    pub path: Option<String>,

    /// The service type identifier for the service that the application
    /// credential is permitted to access. Must be a service type that is
    /// listed in the service catalog and not a code name for a service.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub service: Option<String>,
    // TODO: modify DB so that user_id is not nullable
}
