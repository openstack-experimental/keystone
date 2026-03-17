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

use crate::webauthn::WebauthnError;

/// The response to a hmac get secret request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct HmacGetSecretOutput {
    /// Output of HMAC(Salt 1 || Client Secret).
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = Binary, content_encoding = "base64"))]
    pub output1: String,
    /// Output of HMAC(Salt 2 || Client Secret).
    #[cfg_attr(feature = "openapi", schema(nullable = false, value_type = String, format = Binary, content_encoding = "base64"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(required))]
    pub output2: Option<String>,
}

impl TryFrom<HmacGetSecretOutput> for webauthn_rs_proto::extensions::HmacGetSecretOutput {
    type Error = WebauthnError;

    fn try_from(val: HmacGetSecretOutput) -> Result<Self, Self::Error> {
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

impl From<webauthn_rs_proto::extensions::HmacGetSecretOutput> for HmacGetSecretOutput {
    fn from(val: webauthn_rs_proto::extensions::HmacGetSecretOutput) -> Self {
        Self {
            output1: URL_SAFE.encode(val.output1),
            output2: val.output2.map(|s2| URL_SAFE.encode(s2)),
        }
    }
}
