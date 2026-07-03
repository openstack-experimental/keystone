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
//! Legacy OS-EC2 credential wire types (ADR 0019 §2/§3,
//! `/v3/users/{user_id}/credentials/OS-EC2`).
//!
//! Unlike `/v3/credentials`, this API flattens the `ec2` credential's `blob`
//! into explicit `access`/`secret` fields and never exposes `blob` itself.

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// An EC2 credential, as returned to API clients with `blob` flattened into
/// `access`/`secret`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Ec2Credential {
    /// The plaintext EC2 access key. Also the value hashed
    /// (`SHA-256`) to form the credential's storage ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub access: String,

    /// The plaintext EC2 secret key.
    pub secret: String,

    /// The ID of the user who owns the credential.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub user_id: String,

    /// The project the credential is bound to.
    #[serde(rename = "tenant_id")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: String,

    /// The trust used to create the credential, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_id: Option<String>,
}

/// Single EC2 credential envelope.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Ec2CredentialResponse {
    /// EC2 credential object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub credential: Ec2Credential,
}

/// EC2 credentials list envelope.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Ec2CredentialList {
    /// Collection of EC2 credential objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub credentials: Vec<Ec2Credential>,
}

/// `POST /v3/users/{user_id}/credentials/OS-EC2` request body. Unlike every
/// other Keystone v3 create request, this legacy body is **not** wrapped in
/// a resource key (a historical quirk carried over from the v2.0 EC2
/// credentials API).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Ec2CredentialCreateRequest {
    /// The project to bind the new EC2 credential to.
    #[serde(rename = "tenant_id")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub project_id: String,

    /// The access key. Auto-generated (UUID) when omitted (ADR 0019 §2,
    /// "Automatic Creation").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,

    /// The secret key. Auto-generated (UUID) when omitted (ADR 0019 §2,
    /// "Automatic Creation").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}
