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

#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Region {
    /// The region description.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub description: Option<String>,

    /// Additional region properties.
    #[builder(default)]
    pub extra: Option<Value>,

    /// The ID of the region.
    #[validate(length(min = 1, max = 255))]
    pub id: String,

    /// The ID of the parent region, when this region is nested under another.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub parent_region_id: Option<String>,
}

/// Parameters for creating a new region.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct RegionCreate {
    /// The region description.
    #[validate(length(max = 255))]
    pub description: Option<String>,

    /// Additional region properties.
    pub extra: HashMap<String, Value>,

    /// The ID of the region. A UUID is generated when omitted.
    #[validate(length(min = 1, max = 255))]
    pub id: Option<String>,

    /// The ID of the parent region.
    #[validate(length(max = 255))]
    pub parent_region_id: Option<String>,
}

#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RegionListParameters {
    /// Filters the response by a parent region ID.
    #[validate(length(max = 255))]
    pub parent_region_id: Option<String>,
}

/// Fields that can be changed when updating a region.
///
/// Each field is `None` when the caller did not provide it (leave unchanged)
/// and `Some(..)` to set a new value.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct RegionUpdate {
    /// New region description.
    #[validate(length(max = 255))]
    pub description: Option<String>,

    /// New additional region properties (replaces the existing `extra`).
    pub extra: Option<HashMap<String, Value>>,

    /// New parent region ID.
    #[validate(length(max = 255))]
    pub parent_region_id: Option<String>,
}
