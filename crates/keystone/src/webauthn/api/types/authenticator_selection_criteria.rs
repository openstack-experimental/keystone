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

use super::authenticator_attachment::AuthenticatorAttachment;
use super::resident_key_requirement::ResidentKeyRequirement;
use super::user_verification_policy::UserVerificationPolicy;

/// <https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct AuthenticatorSelectionCriteria {
    /// How the authenticator should be attached to the client machine. Note
    /// this is only a hint. It is not enforced in anyway shape or form. <https://www.w3.org/TR/webauthn/#attachment>.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    /// Hint to the credential to create a resident key. Note this value should
    /// be a member of ResidentKeyRequirement, but client must ignore
    /// unknown values, treating an unknown value as if the member does not
    /// exist. <https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey>.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKeyRequirement>,
    /// Hint to the credential to create a resident key. Note this can not be
    /// enforced or validated, so the authenticator may choose to ignore
    /// this parameter. <https://www.w3.org/TR/webauthn/#resident-credential>.
    pub require_resident_key: bool,
    /// The user verification level to request during registration. Depending on
    /// if this authenticator provides verification may affect future
    /// interactions as this is associated to the credential during
    /// registration.
    pub user_verification: UserVerificationPolicy,
}

impl From<AuthenticatorSelectionCriteria>
    for webauthn_rs_proto::options::AuthenticatorSelectionCriteria
{
    fn from(value: AuthenticatorSelectionCriteria) -> Self {
        Self {
            authenticator_attachment: value.authenticator_attachment.map(Into::into),
            resident_key: value.resident_key.map(Into::into),
            require_resident_key: value.require_resident_key,
            user_verification: value.user_verification.into(),
        }
    }
}

impl From<webauthn_rs_proto::options::AuthenticatorSelectionCriteria>
    for AuthenticatorSelectionCriteria
{
    fn from(value: webauthn_rs_proto::options::AuthenticatorSelectionCriteria) -> Self {
        Self {
            authenticator_attachment: value.authenticator_attachment.map(Into::into),
            require_resident_key: value.require_resident_key,
            resident_key: value.resident_key.map(Into::into),
            user_verification: value.user_verification.into(),
        }
    }
}
