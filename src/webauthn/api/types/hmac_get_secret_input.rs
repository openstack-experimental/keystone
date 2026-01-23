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

/// The inputs to the hmac secret if it was created during registration.
///
/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct HmacGetSecretInput {
    /// Retrieve a symmetric secrets from the authenticator with this input.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub output1: String,
    /// Rotate the secret in the same operation.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output2: Option<String>,
}

impl From<webauthn_rs_proto::extensions::HmacGetSecretInput> for HmacGetSecretInput {
    fn from(val: webauthn_rs_proto::extensions::HmacGetSecretInput) -> Self {
        Self {
            output1: URL_SAFE.encode(val.output1),
            output2: val.output2.map(|s2| URL_SAFE.encode(s2)),
        }
    }
}

impl TryFrom<HmacGetSecretInput> for webauthn_rs_proto::extensions::HmacGetSecretInput {
    type Error = WebauthnError;

    fn try_from(val: HmacGetSecretInput) -> Result<Self, Self::Error> {
        Ok(Self {
            output1: URL_SAFE.decode(val.output1)?.into(),
            output2: val
                .output2
                .map(|s2| URL_SAFE.decode(s2))
                .transpose()?
                .map(Into::into),
        })
    }
}
