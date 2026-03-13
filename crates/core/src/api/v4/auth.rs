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

pub use openstack_keystone_api_types::v4::auth::token::*;

use crate::error::BuilderError;
use crate::identity::types as identity_types;
use crate::token::Token as BackendToken;

impl TryFrom<UserPassword> for identity_types::UserPasswordAuthRequest {
    type Error = BuilderError;

    fn try_from(value: UserPassword) -> Result<Self, Self::Error> {
        let mut upa = identity_types::UserPasswordAuthRequestBuilder::default();
        if let Some(id) = &value.id {
            upa.id(id);
        }
        if let Some(name) = &value.name {
            upa.name(name);
        }
        if let Some(domain) = &value.domain {
            let mut domain_builder = identity_types::DomainBuilder::default();
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

impl TryFrom<&BackendToken> for Token {
    type Error = openstack_keystone_api_types::error::BuilderError;

    fn try_from(value: &BackendToken) -> Result<Self, Self::Error> {
        let mut token = TokenBuilder::default();
        token.user(UserBuilder::default().id(value.user_id()).build()?);
        token.methods(value.methods().clone());
        token.audit_ids(value.audit_ids().clone());
        token.expires_at(*value.expires_at());
        token.build()
    }
}
