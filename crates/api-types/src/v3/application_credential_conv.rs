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
use secrecy::ExposeSecret;

use openstack_keystone_core_types::application_credential as provider_types;

use crate::v3::application_credential::access_rule as api_types_access_rule;
use crate::v3::application_credential::application_credential as api_types_application_credential;

impl From<provider_types::AccessRule> for api_types_access_rule::AccessRule {
    fn from(value: provider_types::AccessRule) -> Self {
        Self {
            id: value.id,
            method: value.method,
            path: value.path,
            service: value.service,
        }
    }
}

impl From<provider_types::ApplicationCredential>
    for api_types_application_credential::ApplicationCredential
{
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
            roles: value.roles.into_iter().map(Into::into).collect(),
            unrestricted: value.unrestricted,
        }
    }
}

impl From<provider_types::ApplicationCredentialCreateResponse>
    for api_types_application_credential::ApplicationCredentialCreated
{
    fn from(value: provider_types::ApplicationCredentialCreateResponse) -> Self {
        Self {
            access_rules: value
                .access_rules
                .map(|rules| rules.into_iter().map(Into::into).collect()),
            description: value.description,
            expires_at: value.expires_at,
            id: value.id,
            name: value.name,
            project_id: value.project_id,
            roles: value.roles.into_iter().map(Into::into).collect(),
            secret: value.secret.expose_secret().to_string(),
            unrestricted: value.unrestricted,
        }
    }
}

impl From<api_types_application_credential::ApplicationCredentialCreate>
    for provider_types::ApplicationCredentialCreateBuilder
{
    fn from(value: api_types_application_credential::ApplicationCredentialCreate) -> Self {
        let mut builder = provider_types::ApplicationCredentialCreateBuilder::default();
        builder.name(value.name);
        builder.roles(value.roles.into_iter().map(Into::into).collect::<Vec<_>>());
        if let Some(v) = value.access_rules {
            builder.access_rules(
                v.into_iter()
                    .map(|r| {
                        provider_types::AccessRuleCreateBuilder::from(r)
                            .build()
                            .unwrap()
                    })
                    .collect::<Vec<_>>(),
            );
        }
        if let Some(v) = value.description {
            builder.description(v);
        }
        if let Some(v) = value.expires_at {
            builder.expires_at(v);
        }
        if let Some(v) = value.unrestricted {
            builder.unrestricted(v);
        }
        builder
    }
}

impl From<api_types_access_rule::AccessRuleCreate> for provider_types::AccessRuleCreateBuilder {
    fn from(value: api_types_access_rule::AccessRuleCreate) -> Self {
        let mut builder = provider_types::AccessRuleCreateBuilder::default();
        if let Some(v) = value.id {
            builder.id(v);
        }
        if let Some(v) = value.method {
            builder.method(v);
        }
        if let Some(v) = value.path {
            builder.path(v);
        }
        if let Some(v) = value.service {
            builder.service(v);
        }
        builder
    }
}

impl From<api_types_application_credential::ApplicationCredentialListParameters>
    for provider_types::ApplicationCredentialListParametersBuilder
{
    fn from(value: api_types_application_credential::ApplicationCredentialListParameters) -> Self {
        let mut builder = provider_types::ApplicationCredentialListParametersBuilder::default();
        if let Some(v) = value.name {
            builder.name(v);
        }
        builder
    }
}
