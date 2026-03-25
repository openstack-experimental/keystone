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

use openstack_keystone_core_types::error::BuilderError;

use crate::v3::auth::token as api_types;

impl TryFrom<api_types::UserPassword>
    for openstack_keystone_core_types::identity::UserPasswordAuthRequest
{
    type Error = BuilderError;

    fn try_from(value: api_types::UserPassword) -> Result<Self, Self::Error> {
        let mut upa =
            openstack_keystone_core_types::identity::UserPasswordAuthRequestBuilder::default();
        if let Some(id) = &value.id {
            upa.id(id);
        }
        if let Some(name) = &value.name {
            upa.name(name);
        }
        if let Some(domain) = &value.domain {
            let mut domain_builder =
                openstack_keystone_core_types::identity::DomainBuilder::default();
            if let Some(id) = &domain.id {
                domain_builder.id(id);
            }
            if let Some(name) = &domain.name {
                domain_builder.name(name);
            }
            upa.domain(domain_builder.build()?);
        }
        upa.password(value.password.clone());
        upa.build()
    }
}

impl TryFrom<&openstack_keystone_core_types::token::Token> for api_types::Token {
    type Error = BuilderError;

    fn try_from(value: &openstack_keystone_core_types::token::Token) -> Result<Self, Self::Error> {
        let mut token = api_types::TokenBuilder::default();
        token.user(
            api_types::UserBuilder::default()
                .id(value.user_id())
                .build()?,
        );
        token.methods(value.methods().clone());
        token.audit_ids(value.audit_ids().clone());
        token.expires_at(*value.expires_at());
        token.build()
    }
}
