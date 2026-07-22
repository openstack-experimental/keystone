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

use std::collections::HashMap;

use derive_builder::Builder;
use serde_json::Value;
use validator::Validate;

use crate::error::BuilderError;

/// An endpoint group: a named set of endpoints selected by `filters`.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct EndpointGroup {
    /// The endpoint group description.
    #[builder(default)]
    pub description: Option<String>,

    /// The filters used to associate endpoints with the group (e.g. by
    /// `interface`, `service_id`, or `region_id`).
    #[builder(default)]
    pub filters: HashMap<String, Value>,

    /// The ID of the endpoint group.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The name of the endpoint group.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
}

/// Parameters for creating a new endpoint group.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct EndpointGroupCreate {
    /// The endpoint group description.
    pub description: Option<String>,

    /// The filters used to associate endpoints with the group.
    pub filters: HashMap<String, Value>,

    /// The ID of the endpoint group. A UUID is generated when omitted.
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The name of the endpoint group.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
}

/// Parameters for filtering the list of endpoint groups.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct EndpointGroupListParameters {
    /// Filters the response by an endpoint group name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,
}

/// Fields that can be changed when updating an endpoint group.
///
/// Each field is `None` when the caller did not provide it (leave unchanged)
/// and `Some(..)` to set a new value.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct EndpointGroupUpdate {
    /// New endpoint group description.
    pub description: Option<String>,

    /// New filters (replaces the existing filters when provided).
    pub filters: Option<HashMap<String, Value>>,

    /// New endpoint group name.
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
}
