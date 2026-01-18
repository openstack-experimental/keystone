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
use utoipa::ToSchema;

/// The Relying Party's requirements for client-side discoverable credentials.
///
/// <https://www.w3.org/TR/webauthn-2/#enumdef-residentkeyrequirement>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum ResidentKeyRequirement {
    /// <https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-discouraged>.
    Discouraged,
    /// ⚠️ In all major browsers preferred is identical in behaviour to
    /// required. You should use required instead. <https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-preferred>.
    Preferred,
    /// <https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-required>.
    Required,
}

impl From<webauthn_rs_proto::options::ResidentKeyRequirement> for ResidentKeyRequirement {
    fn from(value: webauthn_rs_proto::options::ResidentKeyRequirement) -> Self {
        match value {
            webauthn_rs_proto::options::ResidentKeyRequirement::Discouraged => {
                ResidentKeyRequirement::Discouraged
            }
            webauthn_rs_proto::options::ResidentKeyRequirement::Preferred => {
                ResidentKeyRequirement::Preferred
            }
            webauthn_rs_proto::options::ResidentKeyRequirement::Required => {
                ResidentKeyRequirement::Required
            }
        }
    }
}

impl From<ResidentKeyRequirement> for webauthn_rs_proto::options::ResidentKeyRequirement {
    fn from(value: ResidentKeyRequirement) -> Self {
        match value {
            ResidentKeyRequirement::Discouraged => {
                webauthn_rs_proto::options::ResidentKeyRequirement::Discouraged
            }
            ResidentKeyRequirement::Preferred => {
                webauthn_rs_proto::options::ResidentKeyRequirement::Preferred
            }
            ResidentKeyRequirement::Required => {
                webauthn_rs_proto::options::ResidentKeyRequirement::Required
            }
        }
    }
}
