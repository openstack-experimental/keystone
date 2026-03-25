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
//! Federated attribute mapping types.
use uuid::Uuid;

use openstack_keystone_core_types::federation as provider_types;

use crate::error::KeystoneApiError;
use crate::federation::mapping as api_types;

impl From<provider_types::Mapping> for api_types::Mapping {
    fn from(value: provider_types::Mapping) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain_id: value.domain_id,
            idp_id: value.idp_id,
            r#type: value.r#type.into(),
            enabled: value.enabled,
            allowed_redirect_uris: value.allowed_redirect_uris,
            user_id_claim: value.user_id_claim,
            user_name_claim: value.user_name_claim,
            domain_id_claim: value.domain_id_claim,
            groups_claim: value.groups_claim,
            bound_audiences: value.bound_audiences,
            bound_subject: value.bound_subject,
            bound_claims: value.bound_claims,
            oidc_scopes: value.oidc_scopes,
            token_project_id: value.token_project_id,
            token_restriction_id: value.token_restriction_id,
        }
    }
}

impl From<api_types::MappingCreateRequest> for provider_types::Mapping {
    fn from(value: api_types::MappingCreateRequest) -> Self {
        Self {
            id: value.mapping.id.unwrap_or_else(|| Uuid::new_v4().into()),
            name: value.mapping.name,
            domain_id: value.mapping.domain_id,
            idp_id: value.mapping.idp_id,
            r#type: value.mapping.r#type.unwrap_or_default().into(),
            enabled: value.mapping.enabled,
            allowed_redirect_uris: value.mapping.allowed_redirect_uris,
            user_id_claim: value.mapping.user_id_claim,
            user_name_claim: value.mapping.user_name_claim,
            domain_id_claim: value.mapping.domain_id_claim,
            groups_claim: value.mapping.groups_claim,
            bound_audiences: value.mapping.bound_audiences,
            bound_subject: value.mapping.bound_subject,
            bound_claims: value.mapping.bound_claims,
            oidc_scopes: value.mapping.oidc_scopes,
            token_project_id: value.mapping.token_project_id,
            token_restriction_id: value.mapping.token_restriction_id,
        }
    }
}

impl From<api_types::MappingUpdateRequest> for provider_types::MappingUpdate {
    fn from(value: api_types::MappingUpdateRequest) -> Self {
        Self {
            name: value.mapping.name,
            idp_id: value.mapping.idp_id,
            r#type: value.mapping.r#type.map(Into::into),
            enabled: value.mapping.enabled,
            allowed_redirect_uris: value.mapping.allowed_redirect_uris,
            user_id_claim: value.mapping.user_id_claim,
            user_name_claim: value.mapping.user_name_claim,
            domain_id_claim: value.mapping.domain_id_claim,
            groups_claim: value.mapping.groups_claim,
            bound_audiences: value.mapping.bound_audiences,
            bound_subject: value.mapping.bound_subject,
            bound_claims: value.mapping.bound_claims,
            oidc_scopes: value.mapping.oidc_scopes,
            token_project_id: value.mapping.token_project_id,
            token_restriction_id: value.mapping.token_restriction_id,
        }
    }
}

impl From<provider_types::MappingType> for api_types::MappingType {
    fn from(value: provider_types::MappingType) -> Self {
        match value {
            provider_types::MappingType::Oidc => Self::Oidc,
            provider_types::MappingType::Jwt => Self::Jwt,
        }
    }
}

impl From<api_types::MappingType> for provider_types::MappingType {
    fn from(value: api_types::MappingType) -> Self {
        match value {
            api_types::MappingType::Oidc => Self::Oidc,
            api_types::MappingType::Jwt => Self::Jwt,
        }
    }
}

impl TryFrom<api_types::MappingListParameters> for provider_types::MappingListParameters {
    type Error = KeystoneApiError;

    fn try_from(value: api_types::MappingListParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            domain_id: value.domain_id,
            idp_id: value.idp_id,
            limit: value.limit,
            marker: value.marker,
            name: value.name,
            r#type: value.r#type.map(Into::into),
        })
    }
}
