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

/// The authenticator attachment hint. This is NOT enforced, and is only used to
/// help a user select a relevant authenticator type.
///
/// <https://www.w3.org/TR/webauthn/#attachment>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AuthenticatorAttachment {
    /// Request a device that is part of the machine aka inseparable.
    /// <https://www.w3.org/TR/webauthn/#attachment>.
    Platform,
    /// Request a device that can be separated from the machine aka an external
    /// token. <https://www.w3.org/TR/webauthn/#attachment>.
    CrossPlatform,
}

impl From<AuthenticatorAttachment> for webauthn_rs_proto::options::AuthenticatorAttachment {
    fn from(value: AuthenticatorAttachment) -> Self {
        match value {
            AuthenticatorAttachment::CrossPlatform => {
                webauthn_rs_proto::options::AuthenticatorAttachment::CrossPlatform
            }
            AuthenticatorAttachment::Platform => {
                webauthn_rs_proto::options::AuthenticatorAttachment::Platform
            }
        }
    }
}

impl From<webauthn_rs_proto::options::AuthenticatorAttachment> for AuthenticatorAttachment {
    fn from(value: webauthn_rs_proto::options::AuthenticatorAttachment) -> Self {
        match value {
            webauthn_rs_proto::options::AuthenticatorAttachment::CrossPlatform => {
                AuthenticatorAttachment::CrossPlatform
            }
            webauthn_rs_proto::options::AuthenticatorAttachment::Platform => {
                AuthenticatorAttachment::Platform
            }
        }
    }
}
