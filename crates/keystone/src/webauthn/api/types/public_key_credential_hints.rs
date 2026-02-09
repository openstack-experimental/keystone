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

/// A hint as to the class of device that is expected to fulfill this operation.
///
/// <https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhints>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum PublicKeyCredentialHints {
    /// The credential is a platform authenticator.
    ClientDevice,

    /// The credential will come from an external device.
    Hybrid,

    /// The credential is a removable security key.
    SecurityKey,
}

impl From<webauthn_rs_proto::options::PublicKeyCredentialHints> for PublicKeyCredentialHints {
    fn from(value: webauthn_rs_proto::options::PublicKeyCredentialHints) -> Self {
        match value {
            webauthn_rs_proto::options::PublicKeyCredentialHints::ClientDevice => {
                PublicKeyCredentialHints::ClientDevice
            }
            webauthn_rs_proto::options::PublicKeyCredentialHints::Hybrid => {
                PublicKeyCredentialHints::Hybrid
            }
            webauthn_rs_proto::options::PublicKeyCredentialHints::SecurityKey => {
                PublicKeyCredentialHints::SecurityKey
            }
        }
    }
}

impl From<PublicKeyCredentialHints> for webauthn_rs_proto::options::PublicKeyCredentialHints {
    fn from(value: PublicKeyCredentialHints) -> Self {
        match value {
            PublicKeyCredentialHints::ClientDevice => {
                webauthn_rs_proto::options::PublicKeyCredentialHints::ClientDevice
            }
            PublicKeyCredentialHints::Hybrid => {
                webauthn_rs_proto::options::PublicKeyCredentialHints::Hybrid
            }
            PublicKeyCredentialHints::SecurityKey => {
                webauthn_rs_proto::options::PublicKeyCredentialHints::SecurityKey
            }
        }
    }
}
