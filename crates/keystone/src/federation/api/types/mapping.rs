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
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use openstack_keystone_api_types::federation::mapping;

use crate::api::{
    KeystoneApiError,
    common::{QueryParameterPagination, ResourceIdentifier},
};
use crate::federation::types;

pub use mapping::Mapping;
pub use mapping::MappingCreate;
pub use mapping::MappingCreateRequest;
pub use mapping::MappingList;
pub use mapping::MappingListParameters;
pub use mapping::MappingResponse;
pub use mapping::MappingType;
pub use mapping::MappingUpdate;
pub use mapping::MappingUpdateRequest;

impl From<types::Mapping> for Mapping {
    fn from(value: types::Mapping) -> Self {
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

impl From<MappingCreateRequest> for types::Mapping {
    fn from(value: MappingCreateRequest) -> Self {
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

impl From<MappingUpdateRequest> for types::MappingUpdate {
    fn from(value: MappingUpdateRequest) -> Self {
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

impl IntoResponse for types::Mapping {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(MappingResponse {
                mapping: Mapping::from(self),
            }),
        )
            .into_response()
    }
}

impl From<types::MappingType> for MappingType {
    fn from(value: types::MappingType) -> MappingType {
        match value {
            types::MappingType::Oidc => MappingType::Oidc,
            types::MappingType::Jwt => MappingType::Jwt,
        }
    }
}

impl From<MappingType> for types::MappingType {
    fn from(value: MappingType) -> types::MappingType {
        match value {
            MappingType::Oidc => types::MappingType::Oidc,
            MappingType::Jwt => types::MappingType::Jwt,
        }
    }
}

impl TryFrom<MappingListParameters> for types::MappingListParameters {
    type Error = KeystoneApiError;

    fn try_from(value: MappingListParameters) -> Result<Self, Self::Error> {
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

impl ResourceIdentifier for Mapping {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}

impl QueryParameterPagination for MappingListParameters {
    fn get_limit(&self) -> Option<u64> {
        self.limit
    }

    fn set_marker(&mut self, marker: String) -> &mut Self {
        self.marker = Some(marker);
        self
    }
}
