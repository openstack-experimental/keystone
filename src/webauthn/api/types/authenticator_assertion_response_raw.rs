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

use crate::webauthn::WebauthnError;

/// [AuthenticatorAssertionResponseRaw](https://w3c.github.io/webauthn/#authenticatorassertionresponse)
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct AuthenticatorAssertionResponseRaw {
    /// Raw authenticator data.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub authenticator_data: String,
    /// Signed client data.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub client_data_json: String,
    /// Signature.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub signature: String,
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    /// Optional user handle.
    pub user_handle: Option<String>,
}

impl TryFrom<AuthenticatorAssertionResponseRaw>
    for webauthn_rs_proto::auth::AuthenticatorAssertionResponseRaw
{
    type Error = WebauthnError;
    fn try_from(val: AuthenticatorAssertionResponseRaw) -> Result<Self, Self::Error> {
        Ok(Self {
            authenticator_data: URL_SAFE.decode(val.authenticator_data)?.into(),
            client_data_json: URL_SAFE.decode(val.client_data_json)?.into(),
            signature: URL_SAFE.decode(val.signature)?.into(),
            user_handle: val
                .user_handle
                .map(|uh| URL_SAFE.decode(uh))
                .transpose()?
                .map(Into::into),
        })
    }
}

impl From<webauthn_rs_proto::auth::AuthenticatorAssertionResponseRaw>
    for AuthenticatorAssertionResponseRaw
{
    fn from(val: webauthn_rs_proto::auth::AuthenticatorAssertionResponseRaw) -> Self {
        Self {
            authenticator_data: URL_SAFE.encode(val.authenticator_data),
            client_data_json: URL_SAFE.encode(val.client_data_json),
            signature: URL_SAFE.encode(val.signature),
            user_handle: val.user_handle.map(|uh| URL_SAFE.encode(uh)),
        }
    }
}
