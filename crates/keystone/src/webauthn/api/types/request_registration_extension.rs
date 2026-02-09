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

use super::cred_protect::CredProtect;

/// Extension option inputs for PublicKeyCredentialCreationOptions.
///
/// Implements `AuthenticatorExtensionsClientInputs` from the spec.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct RequestRegistrationExtensions {
    /// ⚠️ - This extension result is always unsigned, and only indicates if the
    /// browser requests a residentKey to be created. It has no bearing on
    /// the true rk state of the credential.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    /// The credProtect extension options.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub cred_protect: Option<CredProtect>,
    /// ⚠️ - Browsers support the creation of the secret, but not the retrieval
    /// of it. CTAP2.1 create hmac secret.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_create_secret: Option<bool>,
    /// CTAP2.1 Minimum pin length.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
    /// ⚠️ - Browsers do not support this! Uvm.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uvm: Option<bool>,
}

impl From<RequestRegistrationExtensions>
    for webauthn_rs_proto::extensions::RequestRegistrationExtensions
{
    fn from(value: RequestRegistrationExtensions) -> Self {
        Self {
            cred_props: value.cred_props,
            cred_protect: value.cred_protect.map(Into::into),
            hmac_create_secret: value.hmac_create_secret,
            min_pin_length: value.min_pin_length,
            uvm: value.uvm,
        }
    }
}

impl From<webauthn_rs_proto::extensions::RequestRegistrationExtensions>
    for RequestRegistrationExtensions
{
    fn from(value: webauthn_rs_proto::extensions::RequestRegistrationExtensions) -> Self {
        Self {
            cred_props: value.cred_props,
            cred_protect: value.cred_protect.map(Into::into),
            hmac_create_secret: value.hmac_create_secret,
            min_pin_length: value.min_pin_length,
            uvm: value.uvm,
        }
    }
}
