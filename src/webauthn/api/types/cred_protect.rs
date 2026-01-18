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

use super::credential_protection_policy::CredentialProtectionPolicy;

/// The desired options for the client's use of the credProtect extension
///
/// <https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-credProtect-extension>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct CredProtect {
    /// The credential policy to enforce.
    pub credential_protection_policy: CredentialProtectionPolicy,
    /// Whether it is better for the authenticator to fail to create a
    /// credential rather than ignore the protection policy If no value is
    /// provided, the client treats it as false.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_credential_protection_policy: Option<bool>,
}

impl From<CredProtect> for webauthn_rs_proto::extensions::CredProtect {
    fn from(value: CredProtect) -> Self {
        Self {
            credential_protection_policy: value.credential_protection_policy.into(),
            enforce_credential_protection_policy: value.enforce_credential_protection_policy,
        }
    }
}

impl From<webauthn_rs_proto::extensions::CredProtect> for CredProtect {
    fn from(value: webauthn_rs_proto::extensions::CredProtect) -> Self {
        Self {
            credential_protection_policy: value.credential_protection_policy.into(),
            enforce_credential_protection_policy: value.enforce_credential_protection_policy,
        }
    }
}
