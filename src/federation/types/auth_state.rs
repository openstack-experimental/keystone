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

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::common::types::Scope;

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct AuthState {
    /// Timestamp when the auth will expire.
    #[builder(default)]
    pub expires_at: DateTime<Utc>,

    /// IDP ID.
    pub idp_id: String,

    /// Mapping ID.
    pub mapping_id: String,

    /// Nonce.
    pub nonce: String,

    /// PKCE verifier value.
    pub pkce_verifier: String,

    /// Requested redirect uri.
    pub redirect_uri: String,

    /// Requested scope.
    #[builder(default)]
    pub scope: Option<Scope>,

    /// Auth state (Primary key, CSRF).
    pub state: String,
}
