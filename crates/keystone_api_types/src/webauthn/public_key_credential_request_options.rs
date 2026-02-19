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
use crate::webauthn::{
    allow_credentials::AllowCredentials, public_key_credential_hints::PublicKeyCredentialHints,
    request_authentication_extensions::RequestAuthenticationExtensions,
    user_verification_policy::UserVerificationPolicy,
};

/// The requested options for the authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PublicKeyCredentialRequestOptions {
    /// The set of credentials that are allowed to sign this challenge.
    #[validate(nested)]
    pub allow_credentials: Vec<AllowCredentials>,
    /// The challenge that should be signed by the authenticator.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub challenge: String,
    /// extensions.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub extensions: Option<RequestAuthenticationExtensions>,
    /// Hints defining which types credentials may be used in this operation.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<PublicKeyCredentialHints>>,
    /// The relying party ID.
    #[validate(length(max = 64))]
    pub rp_id: String,
    /// The timeout for the authenticator in case of no interaction.
    pub timeout: Option<u32>,
    /// The verification policy the browser will request.
    pub user_verification: UserVerificationPolicy,
}

impl From<webauthn_rs_proto::auth::PublicKeyCredentialRequestOptions>
    for PublicKeyCredentialRequestOptions
{
    fn from(val: webauthn_rs_proto::auth::PublicKeyCredentialRequestOptions) -> Self {
        Self {
            allow_credentials: val
                .allow_credentials
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
            challenge: URL_SAFE.encode(val.challenge),
            extensions: val.extensions.map(Into::into),
            hints: val
                .hints
                .map(|hints| hints.into_iter().map(Into::into).collect::<Vec<_>>()),
            rp_id: val.rp_id,
            timeout: val.timeout,
            user_verification: val.user_verification.into(),
        }
    }
}

impl TryFrom<PublicKeyCredentialRequestOptions>
    for webauthn_rs_proto::auth::PublicKeyCredentialRequestOptions
{
    type Error = WebauthnError;

    fn try_from(value: PublicKeyCredentialRequestOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            allow_credentials: value
                .allow_credentials
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            challenge: URL_SAFE.decode(value.challenge)?.into(),
            extensions: value.extensions.map(TryInto::try_into).transpose()?,
            hints: value
                .hints
                .map(|hints| hints.into_iter().map(Into::into).collect::<Vec<_>>()),
            rp_id: value.rp_id,
            timeout: value.timeout,
            user_verification: value.user_verification.into(),
        })
    }
}
