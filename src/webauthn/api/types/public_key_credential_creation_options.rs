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

use super::attestation_conveyance_preference::AttestationConveyancePreference;
use super::attestation_format::AttestationFormat;
use super::authenticator_selection_criteria::AuthenticatorSelectionCriteria;
use super::pub_key_cred_params::PubKeyCredParams;
use super::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use super::public_key_credential_hints::PublicKeyCredentialHints;
use super::relying_party::RelyingParty;
use super::request_registration_extension::RequestRegistrationExtensions;
use super::user::User;
use crate::webauthn::WebauthnError;

/// The requested options for the authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PublicKeyCredentialCreationOptions {
    /// The requested attestation level from the device.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    /// The list of attestation formats that the RP will accept.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_formats: Option<Vec<AttestationFormat>>,
    /// Criteria defining which authenticators may be used in this operation.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// The challenge that should be signed by the authenticator.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub challenge: String,
    /// Credential ID's that are excluded from being able to be registered.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    /// extensions.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub extensions: Option<RequestRegistrationExtensions>,
    /// Hints defining which types credentials may be used in this operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<PublicKeyCredentialHints>>,
    /// The set of cryptographic types allowed by this server.
    #[validate(nested)]
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    /// The relying party.
    #[validate(nested)]
    pub rp: RelyingParty,
    /// The timeout for the authenticator in case of no interaction.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(range(min = 1))]
    pub timeout: Option<u32>,
    /// The user.
    #[validate(nested)]
    pub user: User,
}

impl TryFrom<webauthn_rs_proto::attest::PublicKeyCredentialCreationOptions>
    for PublicKeyCredentialCreationOptions
{
    type Error = WebauthnError;
    fn try_from(
        value: webauthn_rs_proto::attest::PublicKeyCredentialCreationOptions,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            attestation: value.attestation.map(Into::into),
            attestation_formats: value
                .attestation_formats
                .map(|afs| afs.into_iter().map(Into::into).collect::<Vec<_>>()),
            authenticator_selection: value.authenticator_selection.map(Into::into),
            challenge: URL_SAFE.encode(&value.challenge),
            exclude_credentials: value
                .exclude_credentials
                .map(|ecs| ecs.into_iter().map(Into::into).collect::<Vec<_>>()),
            extensions: value.extensions.map(Into::into),
            hints: value
                .hints
                .map(|hints| hints.into_iter().map(Into::into).collect::<Vec<_>>()),
            pub_key_cred_params: value
                .pub_key_cred_params
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
            rp: value.rp.into(),
            timeout: value.timeout,
            user: value.user.into(),
        })
    }
}

impl TryFrom<PublicKeyCredentialCreationOptions>
    for webauthn_rs_proto::attest::PublicKeyCredentialCreationOptions
{
    type Error = WebauthnError;

    fn try_from(val: PublicKeyCredentialCreationOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            attestation: val.attestation.map(Into::into),
            attestation_formats: val
                .attestation_formats
                .map(|ats| ats.into_iter().map(Into::into).collect::<Vec<_>>()),
            authenticator_selection: val.authenticator_selection.map(Into::into),
            challenge: URL_SAFE.decode(val.challenge)?.into(),
            exclude_credentials: val
                .exclude_credentials
                .map(|ecs| {
                    ecs.into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?,
            extensions: val.extensions.map(Into::into),
            hints: val
                .hints
                .map(|hints| hints.into_iter().map(Into::into).collect::<Vec<_>>()),
            pub_key_cred_params: val
                .pub_key_cred_params
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
            rp: val.rp.into(),
            timeout: val.timeout,
            user: val.user.try_into()?,
        })
    }
}
