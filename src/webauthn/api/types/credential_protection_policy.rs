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

/// Valid credential protection policies
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[repr(u8)]
pub enum CredentialProtectionPolicy {
    /// This reflects “FIDO_2_0” semantics. In this configuration, performing
    /// some form of user verification is optional with or without
    /// credentialID list. This is the default state of the credential if
    /// the extension is not specified.
    Optional = 1,
    /// In this configuration, credential is discovered only when its
    /// credentialID is provided by the platform or when some form of user
    /// verification is performed.
    OptionalWithCredentialIDList = 2,
    /// This reflects that discovery and usage of the credential MUST be
    /// preceded by some form of user verification.
    Required = 3,
}

impl From<CredentialProtectionPolicy>
    for webauthn_rs_proto::extensions::CredentialProtectionPolicy
{
    fn from(value: CredentialProtectionPolicy) -> Self {
        match value {
            CredentialProtectionPolicy::Optional => {
                webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationOptional
            }
            CredentialProtectionPolicy::OptionalWithCredentialIDList => {
                webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList
            }
            CredentialProtectionPolicy::Required => {
                webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationRequired
            }
        }
    }
}

impl From<webauthn_rs_proto::extensions::CredentialProtectionPolicy>
    for CredentialProtectionPolicy
{
    fn from(value: webauthn_rs_proto::extensions::CredentialProtectionPolicy) -> Self {
        match value {
            webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationOptional => CredentialProtectionPolicy::Optional,
            webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList => CredentialProtectionPolicy::OptionalWithCredentialIDList,
            webauthn_rs_proto::extensions::CredentialProtectionPolicy::UserVerificationRequired => CredentialProtectionPolicy::Required,

        }
    }
}
