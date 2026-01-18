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

/// <https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PublicKeyCredentialDescriptor {
    /// The type of credential.
    pub type_: String,
    /// The credential id.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub id: String,
    /// The allowed transports for this credential. Note this is a hint, and is
    /// NOT enforced.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

impl TryFrom<PublicKeyCredentialDescriptor>
    for webauthn_rs_proto::options::PublicKeyCredentialDescriptor
{
    type Error = WebauthnError;
    fn try_from(value: PublicKeyCredentialDescriptor) -> Result<Self, Self::Error> {
        Ok(Self {
            id: URL_SAFE.decode(value.id)?.into(),
            type_: value.type_,
            transports: value
                .transports
                .map(|trs| trs.into_iter().map(Into::into).collect::<Vec<_>>()),
        })
    }
}

impl From<webauthn_rs_proto::options::PublicKeyCredentialDescriptor>
    for PublicKeyCredentialDescriptor
{
    fn from(value: webauthn_rs_proto::options::PublicKeyCredentialDescriptor) -> Self {
        Self {
            type_: value.type_,
            id: URL_SAFE.encode(&value.id),
            transports: value
                .transports
                .map(|transports| transports.into_iter().map(Into::into).collect::<Vec<_>>()),
        }
    }
}
