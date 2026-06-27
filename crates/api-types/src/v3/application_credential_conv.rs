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

use openstack_keystone_core_types::application_credential as provider_types;

use crate::v3::application_credential as api_types;

impl From<provider_types::AccessRule> for api_types::AccessRule {
    fn from(value: provider_types::AccessRule) -> Self {
        Self {
            id: value.id,
            method: value.method,
            path: value.path,
            service: value.service,
        }
    }
}

impl From<api_types::AccessRuleCreate> for provider_types::AccessRuleCreate {
    fn from(value: api_types::AccessRuleCreate) -> Self {
        Self {
            id: value.id,
            method: value.method,
            path: value.path,
            service: value.service,
            user_id: String::new(), // assigned server-side
        }
    }
}

impl From<provider_types::ApplicationCredential> for api_types::ApplicationCredential {
    fn from(value: provider_types::ApplicationCredential) -> Self {
        Self {
            access_rules: value
                .access_rules
                .map(|rules| rules.into_iter().map(Into::into).collect()),
            description: value.description,
            expires_at: value.expires_at,
            id: value.id,
            name: value.name,
            project_id: value.project_id,
            roles: value.roles,
            unrestricted: value.unrestricted,
            user_id: value.user_id,
        }
    }
}

impl From<api_types::ApplicationCredentialCreate> for provider_types::ApplicationCredentialCreate {
    fn from(value: api_types::ApplicationCredentialCreate) -> Self {
        Self {
            access_rules: value
                .access_rules
                .map(|rules| rules.into_iter().map(Into::into).collect()),
            description: value.description,
            expires_at: value.expires_at,
            id: value.id,
            name: value.name,
            project_id: String::new(), // assigned server-side from token
            roles: value.roles,
            secret: None, // generated server-side
            unrestricted: value.unrestricted,
            user_id: String::new(), // assigned server-side from token
        }
    }
}

impl From<api_types::ApplicationCredentialListParameters>
    for provider_types::ApplicationCredentialListParameters
{
    fn from(value: api_types::ApplicationCredentialListParameters) -> Self {
        Self {
            limit: value.limit,
            marker: value.marker,
            name: value.name,
            user_id: String::new(), // injected from auth context, not from request body
        }
    }
}
