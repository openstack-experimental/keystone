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
use validator::Validate;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Group {
    /// Group ID.
    #[validate(length(max = 64))]
    pub id: String,
    /// Group domain ID.
    #[validate(length(max = 64))]
    pub domain_id: String,
    /// Group name.
    #[validate(length(max = 64))]
    pub name: String,
    /// Group description.
    #[validate(length(max = 255))]
    pub description: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GroupResponse {
    /// group object.
    #[validate(nested)]
    pub group: Group,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GroupCreate {
    /// Group domain ID.
    #[validate(length(max = 64))]
    pub domain_id: String,
    /// Group name.
    #[validate(length(max = 64))]
    pub name: String,
    /// Group description.
    #[validate(length(max = 255))]
    pub description: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GroupCreateRequest {
    /// Group object.
    #[validate(nested)]
    pub group: GroupCreate,
}

/// Groups.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GroupList {
    /// Collection of group objects.
    #[validate(nested)]
    pub groups: Vec<Group>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct GroupListParameters {
    /// Filter users by Domain ID.
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,
    /// Filter users by Name.
    #[validate(length(max = 64))]
    pub name: Option<String>,
}
