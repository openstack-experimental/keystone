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
//! # Passkey registration API types
//!
//! Embedded type webauthn_rs::prelude::CreationChallengeResponse.

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::webauthn::error::WebauthnError;
use crate::webauthn::{
    authenticator_transport::AuthenticatorTransport,
    credential_protection_policy::CredentialProtectionPolicy,
    public_key_credential_creation_options::PublicKeyCredentialCreationOptions,
};

/// Passkey registration request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserPasskeyRegistrationStartRequest {
    /// The description for the passkey (name).
    #[validate(nested)]
    pub passkey: PasskeyCreate,
}

// TODO:
// - remove description from register_start request
/// Passkey information.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PasskeyCreate {
    /// Passkey description.
    #[schema(nullable = false, max_length = 64)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 255))]
    pub description: Option<String>,
}

/// Passkey.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PasskeyResponse {
    /// The description for the passkey (name).
    #[validate(nested)]
    pub passkey: Passkey,
}

/// Passkey information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Passkey {
    /// Credential ID.
    pub credential_id: String,
    /// Credential description.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Passkey challenge.
///
/// This is the WebauthN challenge that need to be signed by the
/// passkey/security device.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserPasskeyRegistrationStartResponse {
    /// The options.
    #[validate(nested)]
    pub public_key: PublicKeyCredentialCreationOptions,
}

impl TryFrom<webauthn_rs_proto::attest::CreationChallengeResponse>
    for UserPasskeyRegistrationStartResponse
{
    type Error = WebauthnError;
    fn try_from(
        value: webauthn_rs_proto::attest::CreationChallengeResponse,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: value.public_key.try_into()?,
        })
    }
}

/// A client response to a registration challenge. This contains all required
/// information to assess and assert trust in a credential's legitimacy,
/// followed by registration to a user.
///
/// You should not need to handle the inner content of this structure - you
/// should provide this to the correctly handling function of Webauthn only.
/// <https://w3c.github.io/webauthn/#iface-pkcredential>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserPasskeyRegistrationFinishRequest {
    /// Optional credential description.
    #[schema(nullable = false, max_length = 64)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub description: Option<String>,
    /// The id of the PublicKey credential, likely in base64.
    ///
    /// This is NEVER actually used in a real registration, because the true
    /// credential ID is taken from the attestation data.
    pub id: String,
    /// The id of the credential, as binary.
    ///
    /// This is NEVER actually used in a real registration, because the true
    /// credential ID is taken from the attestation data.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub raw_id: String,
    /// <https://w3c.github.io/webauthn/#dom-publickeycredential-response>.
    pub response: AuthenticatorAttestationResponseRaw,
    /// The type of credential.
    pub type_: String,
    /// Unsigned Client processed extensions.
    pub extensions: RegistrationExtensionsClientOutputs,
}

impl TryFrom<UserPasskeyRegistrationFinishRequest>
    for webauthn_rs_proto::attest::RegisterPublicKeyCredential
{
    type Error = WebauthnError;
    fn try_from(value: UserPasskeyRegistrationFinishRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            raw_id: URL_SAFE.decode(value.raw_id)?.into(),
            type_: value.type_,
            response: value.response.try_into()?,
            extensions: value.extensions.into(),
        })
    }
}

impl From<webauthn_rs_proto::attest::RegisterPublicKeyCredential>
    for UserPasskeyRegistrationFinishRequest
{
    fn from(value: webauthn_rs_proto::attest::RegisterPublicKeyCredential) -> Self {
        Self {
            description: None,
            id: value.id,
            raw_id: URL_SAFE.encode(value.raw_id),
            type_: value.type_,
            response: value.response.into(),
            extensions: value.extensions.into(),
        }
    }
}

/// <https://w3c.github.io/webauthn/#authenticatorattestationresponse>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct AuthenticatorAttestationResponseRaw {
    /// <https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject>.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub attestation_object: String,
    /// <https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson>.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub client_data_json: String,
    /// <https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-gettransports>.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

impl From<webauthn_rs_proto::attest::AuthenticatorAttestationResponseRaw>
    for AuthenticatorAttestationResponseRaw
{
    fn from(value: webauthn_rs_proto::attest::AuthenticatorAttestationResponseRaw) -> Self {
        Self {
            attestation_object: URL_SAFE.encode(value.attestation_object),
            client_data_json: URL_SAFE.encode(value.client_data_json),
            transports: value
                .transports
                .map(|i| i.into_iter().map(Into::into).collect::<Vec<_>>()),
        }
    }
}

impl TryFrom<AuthenticatorAttestationResponseRaw>
    for webauthn_rs_proto::attest::AuthenticatorAttestationResponseRaw
{
    type Error = WebauthnError;

    fn try_from(value: AuthenticatorAttestationResponseRaw) -> Result<Self, Self::Error> {
        Ok(Self {
            attestation_object: URL_SAFE.decode(value.attestation_object)?.into(),
            client_data_json: URL_SAFE.decode(value.client_data_json)?.into(),
            transports: value
                .transports
                .map(|i| i.into_iter().map(Into::into).collect::<Vec<_>>()),
        })
    }
}

/// <https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientoutputs> The default
/// option here for Options are None, so it can be derived.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct RegistrationExtensionsClientOutputs {
    /// Indicates whether the client used the provided appid extension.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<bool>,
    /// Indicates if the client believes it created a resident key. This
    /// property is managed by the webbrowser, and is NOT SIGNED and CAN NOT
    /// be trusted!
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub cred_props: Option<CredProps>,
    /// Indicates if the client successfully applied a HMAC Secret.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
    /// Indicates if the client successfully applied a credential protection
    /// policy.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredentialProtectionPolicy>,
    /// Indicates the current minimum PIN length.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
}

impl From<RegistrationExtensionsClientOutputs>
    for webauthn_rs_proto::extensions::RegistrationExtensionsClientOutputs
{
    fn from(value: RegistrationExtensionsClientOutputs) -> Self {
        Self {
            appid: value.appid,
            cred_props: value.cred_props.map(Into::into),
            hmac_secret: value.hmac_secret,
            cred_protect: value.cred_protect.map(Into::into),
            min_pin_length: value.min_pin_length,
        }
    }
}

impl From<webauthn_rs_proto::extensions::RegistrationExtensionsClientOutputs>
    for RegistrationExtensionsClientOutputs
{
    fn from(value: webauthn_rs_proto::extensions::RegistrationExtensionsClientOutputs) -> Self {
        Self {
            appid: value.appid,
            cred_props: value.cred_props.map(Into::into),
            hmac_secret: value.hmac_secret,
            cred_protect: value.cred_protect.map(Into::into),
            min_pin_length: value.min_pin_length,
        }
    }
}

/// <https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct CredProps {
    /// A user agent supplied hint that this credential may have created a
    /// resident key. It is returned from the user agent, not the
    /// authenticator meaning that this is an unreliable signal.
    ///
    /// Note that this extension is UNSIGNED and may have been altered by page
    /// javascript.
    pub rk: Option<bool>,
}

impl From<CredProps> for webauthn_rs_proto::extensions::CredProps {
    fn from(value: CredProps) -> Self {
        Self { rk: value.rk }
    }
}

impl From<webauthn_rs_proto::extensions::CredProps> for CredProps {
    fn from(value: webauthn_rs_proto::extensions::CredProps) -> Self {
        Self { rk: value.rk }
    }
}
