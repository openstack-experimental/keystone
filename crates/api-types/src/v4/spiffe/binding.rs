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
//! SPIFFE binding API types.

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::Link;

/// SPIFFE authorization information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum SpiffeAuthorization {
    /// Domain scope authorization.
    Domain {
        /// Domain ID.
        domain_id: String,
        /// Role IDs to authorize.
        role_ids: Option<Vec<String>>,
    },
    /// Project scope authorization.
    Project {
        /// Project ID.
        project_id: String,
        /// Role IDs to authorize.
        role_ids: Option<Vec<String>>,
    },
    /// System scope authorization.
    System {
        /// System ID.
        system_id: String,
        /// Role IDs to authorize.
        role_ids: Option<Vec<String>>,
    },
}

/// SPIFFE binding information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct SpiffeBinding {
    /// Domain ID the binding belongs to.
    #[cfg_attr(feature = "openapi", schema(nullable = false, max_length = 64))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: String,

    /// Flag indicating system-wide identity (system scope).
    pub is_system: bool,

    /// SPIFFE SVID identifier.
    #[cfg_attr(feature = "openapi", schema(max_length = 255, format = Uri))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub svid: String,

    /// Optional user ID the binding maps to.
    #[cfg_attr(feature = "openapi", schema(nullable = false, max_length = 64))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// List of authorizations bound to this identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizations: Option<Vec<SpiffeAuthorization>>,
}

/// SPIFFE binding response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct SpiffeBindingResponse {
    /// Binding object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub binding: SpiffeBinding,
}

/// New SPIFFE binding data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct SpiffeBindingCreate {
    /// Domain ID the binding belongs to.
    #[cfg_attr(feature = "openapi", schema(nullable = false, max_length = 64))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: String,

    /// Flag indicating system-wide identity (system scope).
    pub is_system: bool,

    /// SPIFFE SVID identifier.
    #[cfg_attr(feature = "openapi", schema(max_length = 255, format = Uri))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub svid: String,

    /// Optional user ID the binding maps to.
    #[cfg_attr(feature = "openapi", schema(nullable = false, max_length = 64))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// List of authorizations to bind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizations: Option<Vec<SpiffeAuthorization>>,
}

/// SPIFFE binding create request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct SpiffeBindingCreateRequest {
    /// Binding object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub binding: SpiffeBindingCreate,
}

/// Update SPIFFE binding data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct SpiffeBindingUpdate {
    /// List of authorizations to update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizations: Option<Vec<SpiffeAuthorization>>,
}

/// SPIFFE binding update request.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct SpiffeBindingUpdateRequest {
    /// Binding update object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub binding: SpiffeBindingUpdate,
}

/// SPIFFE binding list parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct SpiffeBindingListParameters {
    /// Domain ID to filter bindings.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,

    /// User ID to filter bindings.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// SPIFFE binding list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct SpiffeBindingList {
    /// Collection of binding objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub bindings: Vec<SpiffeBinding>,

    /// Pagination links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}
