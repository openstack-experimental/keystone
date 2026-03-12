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

/// <https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AttestationConveyancePreference {
    /// Do not request attestation.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-none>.
    None,
    /// Request attestation in a semi-anonymized form.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-indirect>.
    Indirect,
    /// Request attestation in a direct form.
    /// <https://www.w3.org/TR/webauthn/#dom-attestationconveyancepreference-direct>.
    Direct,
}

impl From<webauthn_rs_proto::options::AttestationConveyancePreference>
    for AttestationConveyancePreference
{
    fn from(val: webauthn_rs_proto::options::AttestationConveyancePreference) -> Self {
        match val {
            webauthn_rs_proto::options::AttestationConveyancePreference::Direct => {
                AttestationConveyancePreference::Direct
            }
            webauthn_rs_proto::options::AttestationConveyancePreference::Indirect => {
                AttestationConveyancePreference::Indirect
            }
            webauthn_rs_proto::options::AttestationConveyancePreference::None => {
                AttestationConveyancePreference::None
            }
        }
    }
}

impl From<AttestationConveyancePreference>
    for webauthn_rs_proto::options::AttestationConveyancePreference
{
    fn from(val: AttestationConveyancePreference) -> Self {
        match val {
            AttestationConveyancePreference::Direct => {
                webauthn_rs_proto::options::AttestationConveyancePreference::Direct
            }
            AttestationConveyancePreference::Indirect => {
                webauthn_rs_proto::options::AttestationConveyancePreference::Indirect
            }
            AttestationConveyancePreference::None => {
                webauthn_rs_proto::options::AttestationConveyancePreference::None
            }
        }
    }
}
