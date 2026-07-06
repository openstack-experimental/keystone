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
//! # SCIM v2 error envelope (ADR 0024 §10)
//!
//! Most SCIM failure modes carry no RFC 7644-specific body: the Realm
//! Activation Gate (§2.B, 403) is enforced entirely inside the
//! [`crate::api::api_key_auth::ScimRealmAuth`] extractor before a handler
//! ever runs, and the Ownership Fencing Algorithm (§3.C, 404) is
//! indistinguishable from "does not exist" by design — both are adequately
//! represented by the generic [`KeystoneApiError`] envelope. Only the
//! collision cases RFC 7644 §3.12 mandates a `scimType` for get their own
//! variant here, shared by Users (this PR) and Groups (a later PR).

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use openstack_keystone_core::api::KeystoneApiError;

/// `urn:ietf:params:scim:api:messages:2.0:Error` schema URI.
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// RFC 7644 §3.12 SCIM error response body.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimErrorBody {
    pub schemas: Vec<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    pub detail: String,
}

/// SCIM v2 resource-handler error.
#[derive(Debug)]
pub enum ScimApiError {
    /// `userName`/`displayName`/`externalId` collision (409, `scimType:
    /// "uniqueness"`, ADR 0024 §3.C/§3.D).
    Uniqueness(String),
    /// Cross-realm/manual-user membership reference, or membership count
    /// exceeding the §11 cap (400, `scimType: "invalidValue"`, ADR 0024 §7,
    /// §11).
    InvalidValue(String),
    /// Everything else — reuses the generic Keystone error envelope.
    Api(KeystoneApiError),
}

impl IntoResponse for ScimApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Uniqueness(detail) => (
                StatusCode::CONFLICT,
                Json(ScimErrorBody {
                    schemas: vec![SCIM_ERROR_SCHEMA.to_string()],
                    status: StatusCode::CONFLICT.as_str().to_string(),
                    scim_type: Some("uniqueness".to_string()),
                    detail,
                }),
            )
                .into_response(),
            Self::InvalidValue(detail) => (
                StatusCode::BAD_REQUEST,
                Json(ScimErrorBody {
                    schemas: vec![SCIM_ERROR_SCHEMA.to_string()],
                    status: StatusCode::BAD_REQUEST.as_str().to_string(),
                    scim_type: Some("invalidValue".to_string()),
                    detail,
                }),
            )
                .into_response(),
            Self::Api(e) => e.into_response(),
        }
    }
}

impl<E> From<E> for ScimApiError
where
    E: Into<KeystoneApiError>,
{
    fn from(value: E) -> Self {
        Self::Api(value.into())
    }
}
