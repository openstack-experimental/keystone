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
use validator::Validate;

use crate::webauthn::WebauthnError;
use crate::webauthn::hmac_get_secret_input::HmacGetSecretInput;

/// Extension option inputs for PublicKeyCredentialRequestOptions.
///
/// Implements AuthenticatorExtensionsClientInputs from the spec.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct RequestAuthenticationExtensions {
    /// The appid extension options.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    /// ⚠️ - Browsers do not support this!
    /// <https://bugs.chromium.org/p/chromium/issues/detail?id=1023225> Hmac get secret.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub hmac_get_secret: Option<HmacGetSecretInput>,
    /// ⚠️ - Browsers do not support this! Uvm.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uvm: Option<bool>,
}

impl From<webauthn_rs_proto::extensions::RequestAuthenticationExtensions>
    for RequestAuthenticationExtensions
{
    fn from(value: webauthn_rs_proto::extensions::RequestAuthenticationExtensions) -> Self {
        Self {
            appid: value.appid,
            hmac_get_secret: value.hmac_get_secret.map(Into::into),
            uvm: value.uvm,
        }
    }
}

impl TryFrom<RequestAuthenticationExtensions>
    for webauthn_rs_proto::extensions::RequestAuthenticationExtensions
{
    type Error = WebauthnError;

    fn try_from(value: RequestAuthenticationExtensions) -> Result<Self, Self::Error> {
        Ok(Self {
            appid: value.appid,
            hmac_get_secret: value.hmac_get_secret.map(TryInto::try_into).transpose()?,
            uvm: value.uvm,
        })
    }
}
