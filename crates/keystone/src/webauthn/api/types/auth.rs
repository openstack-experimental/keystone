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
//! # Passkey authentication types

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use super::authentication_extensions_client_outputs::AuthenticationExtensionsClientOutputs;
use super::authenticator_assertion_response_raw::AuthenticatorAssertionResponseRaw;
use super::public_key_credential_request_options::PublicKeyCredentialRequestOptions;
use crate::webauthn::WebauthnError;

/// Request for initialization of the passkey authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PasskeyAuthenticationStartRequest {
    /// The user authentication data.
    #[validate(nested)]
    pub passkey: PasskeyUserAuthenticationRequest,
}

/// Request for initialization of the passkey authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PasskeyUserAuthenticationRequest {
    /// The ID of the user that is authenticating.
    pub user_id: String,
}

/// Passkey Authorization challenge.
///
/// A JSON serializable challenge which is issued to the user's webbrowser for
/// handling. This is meant to be opaque, that is, you should not need to
/// inspect or alter the content of the struct - you should serialise it and
/// transmit it to the client only.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PasskeyAuthenticationStartResponse {
    /// The options.
    #[validate(nested)]
    pub public_key: PublicKeyCredentialRequestOptions,
    /// The mediation requested.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediation: Option<Mediation>,
}

impl From<webauthn_rs::prelude::RequestChallengeResponse> for PasskeyAuthenticationStartResponse {
    fn from(val: webauthn_rs::prelude::RequestChallengeResponse) -> Self {
        Self {
            public_key: val.public_key.into(),
            mediation: val.mediation.map(Into::into),
        }
    }
}

/// Request in resident key workflows that conditional mediation should be used
/// in the UI, or not.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum Mediation {
    /// Discovered credentials are presented to the user in a dialog.
    /// Conditional UI is used. See <https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Conditional-UI>
    /// <https://w3c.github.io/webappsec-credential-management/#enumdef-credentialmediationrequirement>.
    Conditional,
}

impl From<webauthn_rs_proto::auth::Mediation> for Mediation {
    fn from(value: webauthn_rs_proto::auth::Mediation) -> Self {
        match value {
            webauthn_rs_proto::auth::Mediation::Conditional => Mediation::Conditional,
        }
    }
}

impl From<Mediation> for webauthn_rs_proto::auth::Mediation {
    fn from(value: Mediation) -> Self {
        match value {
            Mediation::Conditional => webauthn_rs_proto::auth::Mediation::Conditional,
        }
    }
}

/// A client response to an authentication challenge. This contains all required
/// information to asses and assert trust in a credentials legitimacy, followed
/// by authentication to a user.
///
/// You should not need to handle the inner content of this structure - you
/// should provide this to the correctly handling function of Webauthn only.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct PasskeyAuthenticationFinishRequest {
    /// The credential Id, likely base64.
    pub id: String,
    /// Unsigned Client processed extensions.
    #[validate(nested)]
    pub extensions: AuthenticationExtensionsClientOutputs,
    /// The binary of the credential id.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub raw_id: String,
    /// The authenticator response.
    #[validate(nested)]
    pub response: AuthenticatorAssertionResponseRaw,
    /// The authenticator type.
    pub type_: String,
    /// The ID of the user.
    #[validate(length(max = 64))]
    pub user_id: String,
}

impl TryFrom<PasskeyAuthenticationFinishRequest> for webauthn_rs::prelude::PublicKeyCredential {
    type Error = WebauthnError;
    fn try_from(req: PasskeyAuthenticationFinishRequest) -> Result<Self, Self::Error> {
        Ok(webauthn_rs::prelude::PublicKeyCredential {
            id: req.id,
            extensions: req.extensions.try_into()?,
            raw_id: URL_SAFE.decode(req.raw_id)?.into(),
            response: req.response.try_into()?,
            type_: req.type_,
        })
    }
}
