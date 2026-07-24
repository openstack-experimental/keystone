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
//! User resource types.

use serde::{Deserialize, Serialize};

pub use crate::v3::user::{
    Federation, FederationProtocol, User, UserCreate, UserCreateRequest, UserList, UserOptions,
    UserResponse, UserUpdateRequest,
};

/// User list parameters.
///
/// V4 extends the v3 listing with a `type` filter; this is intentionally a
/// v4-only parameter (Python Keystone does not support it on v3).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserListParameters {
    /// Filter users by Domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,

    /// Filter users by Name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,

    /// Filter users by the federated unique ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub unique_id: Option<String>,

    /// Filter users by type (`local`, `federated`, `nonlocal`, `all`).
    #[serde(rename = "type")]
    pub user_type: Option<UserType>,
}

/// User type filter for listing users.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum UserType {
    /// All users (default behavior).
    All,
    /// Federated users only.
    Federated,
    /// Local users only.
    Local,
    /// Non-local users only.
    NonLocal,
    /// Service account users only.
    #[serde(rename = "service_account")]
    ServiceAccount,
}
