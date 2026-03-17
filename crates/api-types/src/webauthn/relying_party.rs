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

/// Relying Party Entity.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RelyingParty {
    /// The id of the relying party.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
    /// The name of the relying party.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: String,
}

impl From<RelyingParty> for webauthn_rs_proto::options::RelyingParty {
    fn from(value: RelyingParty) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<webauthn_rs_proto::options::RelyingParty> for RelyingParty {
    fn from(value: webauthn_rs_proto::options::RelyingParty) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}
