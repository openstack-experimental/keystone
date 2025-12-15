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

use super::super::types::WebauthnCredential;
use crate::db::entity::webauthn_credential;

mod create;
mod list;

pub use create::create;
pub use list::list;

impl From<webauthn_credential::Model> for WebauthnCredential {
    fn from(value: webauthn_credential::Model) -> Self {
        Self {
            credential_id: value.credential_id,
            description: value.description,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::db::entity::webauthn_credential;
    use base64urlsafedata::HumanBinaryData;
    use chrono::NaiveDateTime;
    use webauthn_rs::prelude::*;
    use webauthn_rs_proto::*;

    pub(super) fn get_fake_passkey() -> Passkey {
        Credential {
            counter: 1,
            transports: None,
            cred_id: HumanBinaryData::from(vec![
                179, 64, 237, 0, 28, 248, 197, 30, 213, 228, 250, 139, 28, 11, 156, 130, 69, 242,
                21, 48, 84, 77, 103, 163, 66, 204, 167, 147, 82, 214, 212,
            ]),
            cred: COSEKey {
                type_: COSEAlgorithm::ES256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: [
                        187, 71, 18, 101, 166, 110, 166, 38, 116, 119, 74, 4, 183, 104, 24, 46,
                        245, 24, 227, 143, 161, 136, 37, 186, 140, 221, 228, 115, 81, 175, 50, 51,
                    ]
                    .to_vec()
                    .into(),
                    y: [
                        13, 59, 59, 158, 149, 197, 116, 228, 99, 12, 235, 185, 190, 110, 251, 154,
                        226, 143, 75, 26, 44, 136, 244, 245, 243, 4, 40, 223, 22, 253, 224, 95,
                    ]
                    .to_vec()
                    .into(),
                }),
            },
            user_verified: false,
            backup_eligible: false,
            backup_state: false,
            registration_policy: UserVerificationPolicy::Discouraged_DO_NOT_USE,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation {
                data: ParsedAttestationData::None,
                metadata: AttestationMetadata::None,
            },
            attestation_format: AttestationFormat::None,
        }
        .into()
    }

    pub(super) fn get_mock<S: AsRef<str>>(id: S) -> webauthn_credential::Model {
        webauthn_credential::Model {
            id: 1,
            user_id: id.as_ref().to_string(),
            credential_id: "cred".into(),
            description: Some("fake".into()),
            passkey: serde_json::to_string(&get_fake_passkey()).unwrap(),
            r#type: "cross-platform".into(),
            aaguid: Some("aaguid".into()),
            created_at: NaiveDateTime::default(),
            last_used_at: None,
            last_updated_at: None,
        }
    }
}
