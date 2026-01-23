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

/// <https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AuthenticatorTransport {
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-ble>.
    Ble,
    /// Hybrid transport, formerly caBLE. Part of the level 3 draft
    /// specification. <https://w3c.github.io/webauthn/#dom-authenticatortransport-hybrid>.
    Hybrid,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-internal>.
    Internal,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-nfc>.
    Nfc,
    /// Test transport; used for Windows 10.
    Test,
    /// An unknown transport was provided - it will be ignored.
    Unknown,
    /// <https://www.w3.org/TR/webauthn/#dom-authenticatortransport-usb>.
    Usb,
}

impl From<AuthenticatorTransport> for webauthn_rs_proto::options::AuthenticatorTransport {
    fn from(value: AuthenticatorTransport) -> Self {
        match value {
            AuthenticatorTransport::Ble => webauthn_rs_proto::options::AuthenticatorTransport::Ble,
            AuthenticatorTransport::Hybrid => {
                webauthn_rs_proto::options::AuthenticatorTransport::Hybrid
            }
            AuthenticatorTransport::Internal => {
                webauthn_rs_proto::options::AuthenticatorTransport::Internal
            }
            AuthenticatorTransport::Nfc => webauthn_rs_proto::options::AuthenticatorTransport::Nfc,
            AuthenticatorTransport::Test => {
                webauthn_rs_proto::options::AuthenticatorTransport::Test
            }
            AuthenticatorTransport::Unknown => {
                webauthn_rs_proto::options::AuthenticatorTransport::Unknown
            }
            AuthenticatorTransport::Usb => webauthn_rs_proto::options::AuthenticatorTransport::Usb,
        }
    }
}

impl From<webauthn_rs_proto::options::AuthenticatorTransport> for AuthenticatorTransport {
    fn from(value: webauthn_rs_proto::options::AuthenticatorTransport) -> Self {
        match value {
            webauthn_rs_proto::options::AuthenticatorTransport::Ble => AuthenticatorTransport::Ble,
            webauthn_rs_proto::options::AuthenticatorTransport::Hybrid => {
                AuthenticatorTransport::Hybrid
            }
            webauthn_rs_proto::options::AuthenticatorTransport::Internal => {
                AuthenticatorTransport::Internal
            }
            webauthn_rs_proto::options::AuthenticatorTransport::Nfc => AuthenticatorTransport::Nfc,
            webauthn_rs_proto::options::AuthenticatorTransport::Test => {
                AuthenticatorTransport::Test
            }
            webauthn_rs_proto::options::AuthenticatorTransport::Unknown => {
                AuthenticatorTransport::Unknown
            }
            webauthn_rs_proto::options::AuthenticatorTransport::Usb => AuthenticatorTransport::Usb,
        }
    }
}
