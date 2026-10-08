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
//
// SPDX-License-Identifier: Apache-2.0
//! OAuth2 consent API types: the applications a user has approved.

use serde::{Deserialize, Serialize};

/// An application (OAuth2 client) the user approved and that is remembered,
/// so the consent page is skipped while the approved scopes cover the
/// request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2Consent {
    /// The approved client.
    pub client_id: String,

    /// Display name of the client, when it still exists.
    pub client_name: Option<String>,

    /// The approved scopes.
    pub scopes: Vec<String>,

    /// Authorization target the approval is limited to (`openstack:api`).
    pub authorization_target: Option<String>,

    /// UTC epoch seconds the user first approved the client.
    pub granted_at: i64,

    /// UTC epoch seconds the approved scopes last changed.
    pub updated_at: i64,
}

/// The applications a user has approved.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2ConsentList {
    /// The approved applications.
    pub consents: Vec<Oauth2Consent>,
}
