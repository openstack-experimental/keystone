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

use openstack_keystone_core_types::credential as provider_types;

use crate::v3::credential as api_types;

impl From<provider_types::Credential> for api_types::Credential {
    fn from(value: provider_types::Credential) -> Self {
        Self {
            id: value.id,
            blob: value.blob,
            project_id: value.project_id,
            r#type: value.r#type,
            user_id: value.user_id,
            extra: value.extra.unwrap_or_default(),
        }
    }
}

impl From<api_types::CredentialListParameters> for provider_types::CredentialListParameters {
    fn from(value: api_types::CredentialListParameters) -> Self {
        Self {
            r#type: value.r#type,
            user_id: value.user_id,
        }
    }
}

impl From<api_types::CredentialCreateRequest> for provider_types::CredentialCreate {
    fn from(value: api_types::CredentialCreateRequest) -> Self {
        let credential = value.credential;
        Self {
            id: None,
            blob: credential.blob,
            r#type: credential.r#type,
            project_id: credential.project_id,
            user_id: credential.user_id,
            extra: if credential.extra.is_empty() {
                None
            } else {
                Some(credential.extra)
            },
        }
    }
}

impl From<api_types::CredentialUpdateRequest> for provider_types::CredentialUpdate {
    fn from(value: api_types::CredentialUpdateRequest) -> Self {
        let credential = value.credential;
        Self {
            blob: credential.blob,
            project_id: credential.project_id,
            r#type: credential.r#type,
        }
    }
}
