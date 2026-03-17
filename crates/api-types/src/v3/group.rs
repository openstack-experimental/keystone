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

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Group {
    /// Group ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
    /// Group domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: String,
    /// Group name.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub name: String,
    /// Group description.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub description: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct GroupResponse {
    /// group object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub group: Group,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct GroupCreate {
    /// Group domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: String,
    /// Group name.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub name: String,
    /// Group description.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub description: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct GroupCreateRequest {
    /// Group object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub group: GroupCreate,
}

/// Groups.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct GroupList {
    /// Collection of group objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub groups: Vec<Group>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct GroupListParameters {
    /// Filter users by Domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,
    /// Filter users by Name.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub name: Option<String>,
}
