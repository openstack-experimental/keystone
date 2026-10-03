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

use derive_builder::Builder;
use serde::Serialize;
use validator::Validate;

use crate::error::BuilderError;

/// Registered limit: the default value of a resource for a service/region.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RegisteredLimit {
    /// The default limit value (`-1` means unlimited).
    #[validate(range(min = -1))]
    pub default_limit: i32,

    /// The registered limit description.
    #[builder(default)]
    #[validate(length(max = 65535))]
    pub description: Option<String>,

    /// The ID of the registered limit.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The ID of the region.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub region_id: Option<String>,

    /// The name of the resource.
    #[validate(length(min = 1, max = 255))]
    pub resource_name: String,

    /// The ID of the service.
    #[validate(length(min = 1, max = 255))]
    pub service_id: String,
}

/// Parameters for creating a registered limit.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RegisteredLimitCreate {
    /// The default limit value (`-1` means unlimited).
    #[validate(range(min = -1))]
    pub default_limit: i32,

    /// The registered limit description.
    #[builder(default)]
    #[validate(length(max = 65535))]
    pub description: Option<String>,

    /// The ID of the registered limit. A UUID is generated when omitted.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The ID of the region.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub region_id: Option<String>,

    /// The name of the resource.
    #[validate(length(min = 1, max = 255))]
    pub resource_name: String,

    /// The ID of the service.
    #[validate(length(min = 1, max = 255))]
    pub service_id: String,
}

/// Filters for listing registered limits.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RegisteredLimitListParameters {
    /// Pagination controls (limit/marker/page_reverse).
    #[builder(default)]
    pub pagination: crate::ListPagination,

    /// Filters the response by a region ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub region_id: Option<String>,

    /// Filters the response by a resource name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub resource_name: Option<String>,

    /// Filters the response by a service ID.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub service_id: Option<String>,
}

/// Fields that can be changed when updating a registered limit.
///
/// `None` means "leave unchanged". For the nullable attributes
/// `Some(None)` resets the value.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RegisteredLimitUpdate {
    /// New default limit value.
    #[builder(default)]
    #[validate(range(min = -1))]
    pub default_limit: Option<i32>,

    /// New description.
    #[builder(default)]
    #[validate(length(max = 65535))]
    pub description: Option<Option<String>>,

    /// New region ID.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub region_id: Option<Option<String>>,

    /// New resource name.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub resource_name: Option<String>,

    /// New service ID.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub service_id: Option<String>,
}
