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

use super::hmac_get_secret_output::HmacGetSecretOutput;
use crate::webauthn::WebauthnError;

/// [AuthenticationExtensionsClientOutputs](https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientoutputs)
///
/// The default option here for Options are None, so it can be derived
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct AuthenticationExtensionsClientOutputs {
    /// Indicates whether the client used the provided appid extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub appid: Option<bool>,
    /// The response to a hmac get secret request.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    #[validate(nested)]
    pub hmac_get_secret: Option<HmacGetSecretOutput>,
}

impl TryFrom<AuthenticationExtensionsClientOutputs>
    for webauthn_rs_proto::extensions::AuthenticationExtensionsClientOutputs
{
    type Error = WebauthnError;
    fn try_from(val: AuthenticationExtensionsClientOutputs) -> Result<Self, Self::Error> {
        Ok(Self {
            appid: val.appid,
            hmac_get_secret: val.hmac_get_secret.map(TryInto::try_into).transpose()?,
        })
    }
}

impl From<webauthn_rs_proto::extensions::AuthenticationExtensionsClientOutputs>
    for AuthenticationExtensionsClientOutputs
{
    fn from(value: webauthn_rs_proto::extensions::AuthenticationExtensionsClientOutputs) -> Self {
        Self {
            appid: value.appid,
            hmac_get_secret: value.hmac_get_secret.map(Into::into),
        }
    }
}
