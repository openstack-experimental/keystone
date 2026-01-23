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

/// The type of attestation on the credential.
///
/// <https://www.iana.org/assignments/webauthn/webauthn.xhtml>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum AttestationFormat {
    /// Packed attestation.
    Packed,
    /// TPM attestation (like Microsoft).
    Tpm,
    /// Android hardware attestation.
    AndroidKey,
    /// Older Android Safety Net.
    AndroidSafetyNet,
    /// Old U2F attestation type.
    FIDOU2F,
    /// Apple touchID/faceID.
    AppleAnonymous,
    /// No attestation.
    None,
}

impl From<webauthn_rs_proto::options::AttestationFormat> for AttestationFormat {
    fn from(value: webauthn_rs_proto::options::AttestationFormat) -> Self {
        match value {
            webauthn_rs_proto::options::AttestationFormat::AndroidKey => {
                AttestationFormat::AndroidKey
            }
            webauthn_rs_proto::options::AttestationFormat::AndroidSafetyNet => {
                AttestationFormat::AndroidSafetyNet
            }
            webauthn_rs_proto::options::AttestationFormat::AppleAnonymous => {
                AttestationFormat::AppleAnonymous
            }
            webauthn_rs_proto::options::AttestationFormat::FIDOU2F => AttestationFormat::FIDOU2F,
            webauthn_rs_proto::options::AttestationFormat::None => AttestationFormat::None,
            webauthn_rs_proto::options::AttestationFormat::Packed => AttestationFormat::Packed,
            webauthn_rs_proto::options::AttestationFormat::Tpm => AttestationFormat::Tpm,
        }
    }
}

impl From<AttestationFormat> for webauthn_rs_proto::options::AttestationFormat {
    fn from(value: AttestationFormat) -> Self {
        match value {
            AttestationFormat::AndroidKey => {
                webauthn_rs_proto::options::AttestationFormat::AndroidKey
            }
            AttestationFormat::AndroidSafetyNet => {
                webauthn_rs_proto::options::AttestationFormat::AndroidSafetyNet
            }
            AttestationFormat::AppleAnonymous => {
                webauthn_rs_proto::options::AttestationFormat::AppleAnonymous
            }
            AttestationFormat::FIDOU2F => webauthn_rs_proto::options::AttestationFormat::FIDOU2F,
            AttestationFormat::None => webauthn_rs_proto::options::AttestationFormat::None,
            AttestationFormat::Packed => webauthn_rs_proto::options::AttestationFormat::Packed,
            AttestationFormat::Tpm => webauthn_rs_proto::options::AttestationFormat::Tpm,
        }
    }
}
