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
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use super::authenticator_transport::AuthenticatorTransport;
use crate::webauthn::WebauthnError;

/// A descriptor of a credential that can be used.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct AllowCredentials {
    /// The id of the credential.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub id: String,
    /// <https://www.w3.org/TR/webauthn/#transport> may be usb, nfc, ble, internal.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
    /// The type of credential.
    pub type_: String,
}

impl From<webauthn_rs_proto::options::AllowCredentials> for AllowCredentials {
    fn from(val: webauthn_rs_proto::options::AllowCredentials) -> Self {
        Self {
            id: URL_SAFE.encode(val.id),
            transports: val
                .transports
                .map(|tr| tr.into_iter().map(Into::into).collect::<Vec<_>>()),
            type_: val.type_,
        }
    }
}

impl TryFrom<AllowCredentials> for webauthn_rs_proto::options::AllowCredentials {
    type Error = WebauthnError;

    fn try_from(val: AllowCredentials) -> Result<Self, Self::Error> {
        Ok(Self {
            id: URL_SAFE.decode(val.id)?.into(),
            transports: val
                .transports
                .map(|tr| tr.into_iter().map(Into::into).collect::<Vec<_>>()),
            type_: val.type_,
        })
    }
}
