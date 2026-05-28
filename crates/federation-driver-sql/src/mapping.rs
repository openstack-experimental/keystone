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
use std::collections::HashMap;

use sea_orm::entity::*;
use serde_json::Value;
use tracing::error;

use openstack_keystone_core::federation::error::FederationProviderError;
use openstack_keystone_core_types::federation::*;

use crate::entity::{
    federated_mapping as db_federated_mapping, sea_orm_active_enums::MappingType as db_mapping_type,
};

mod create;
mod delete;
mod get;
mod list;
mod update;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::list;
pub use update::update;

impl From<MappingType> for db_mapping_type {
    fn from(value: MappingType) -> db_mapping_type {
        match value {
            MappingType::Oidc => db_mapping_type::Oidc,
            MappingType::Jwt => db_mapping_type::Jwt,
        }
    }
}

impl From<&MappingType> for db_mapping_type {
    fn from(value: &MappingType) -> db_mapping_type {
        match value {
            MappingType::Oidc => db_mapping_type::Oidc,
            MappingType::Jwt => db_mapping_type::Jwt,
        }
    }
}

impl TryFrom<Mapping> for db_federated_mapping::ActiveModel {
    type Error = FederationProviderError;
    fn try_from(mapping: Mapping) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(mapping.id.clone()),
            domain_id: Set(mapping.domain_id.clone()),
            name: Set(mapping.name.clone()),
            idp_id: Set(mapping.idp_id.clone()),
            r#type: Set(mapping.r#type.into()),
            enabled: Set(mapping.enabled),
            allowed_redirect_uris: mapping
                .allowed_redirect_uris
                .clone()
                .map(|x| Set(x.join(",")))
                .unwrap_or(NotSet)
                .into(),
            user_id_claim: Set(mapping.user_id_claim.clone()),
            user_name_claim: Set(mapping.user_name_claim.clone()),
            domain_id_claim: mapping
                .domain_id_claim
                .clone()
                .map(Set)
                .unwrap_or(NotSet)
                .into(),
            groups_claim: mapping
                .groups_claim
                .clone()
                .map(Set)
                .unwrap_or(NotSet)
                .into(),
            bound_audiences: mapping
                .bound_audiences
                .clone()
                .map(|x| Set(x.join(",")))
                .unwrap_or(NotSet)
                .into(),
            bound_subject: mapping
                .bound_subject
                .clone()
                .map(Set)
                .unwrap_or(NotSet)
                .into(),
            bound_claims: if !mapping.bound_claims.is_empty() {
                Set(Some(serde_json::to_value(&mapping.bound_claims)?))
            } else {
                NotSet
            },
            oidc_scopes: mapping
                .oidc_scopes
                .clone()
                .map(|x| Set(x.join(",")))
                .unwrap_or(NotSet)
                .into(),
            token_project_id: mapping
                .token_project_id
                .clone()
                .map(Set)
                .unwrap_or(NotSet)
                .into(),
            token_restriction_id: mapping
                .token_restriction_id
                .clone()
                .map(Set)
                .unwrap_or(NotSet)
                .into(),
        })
    }
}

impl TryFrom<db_federated_mapping::Model> for Mapping {
    type Error = FederationProviderError;

    fn try_from(value: db_federated_mapping::Model) -> Result<Self, Self::Error> {
        let mut builder = MappingBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name);
        builder.idp_id(value.idp_id);
        if let Some(val) = &value.domain_id {
            builder.domain_id(val);
        }
        builder.r#type(match value.r#type {
            db_mapping_type::Oidc => MappingType::Oidc,
            db_mapping_type::Jwt => MappingType::Jwt,
        });
        builder.enabled(value.enabled);
        if let Some(val) = &value.allowed_redirect_uris
            && !val.is_empty()
        {
            builder.allowed_redirect_uris(Vec::from_iter(val.split(",").map(Into::into)));
        }
        builder.user_id_claim(value.user_id_claim);
        builder.user_name_claim(value.user_name_claim);
        if let Some(val) = &value.domain_id_claim {
            builder.domain_id_claim(val);
        }
        if let Some(val) = &value.groups_claim {
            builder.groups_claim(val);
        }
        if let Some(val) = &value.bound_audiences
            && !val.is_empty()
        {
            builder.bound_audiences(Vec::from_iter(val.split(",").map(Into::into)));
        }
        if let Some(val) = &value.bound_subject {
            builder.bound_subject(val);
        }
        if let Some(val) = value.bound_claims {
            builder.bound_claims(
                serde_json::from_value::<HashMap<String, Value>>(val)
                    .inspect_err(|e| error!("failed to deserialize mapping additional claims: {e}"))
                    .unwrap_or_default(),
            );
        }
        if let Some(val) = &value.oidc_scopes
            && !val.is_empty()
        {
            builder.oidc_scopes(Vec::from_iter(val.split(",").map(Into::into)));
        }
        if let Some(val) = &value.token_project_id {
            builder.token_project_id(val);
        }
        if let Some(val) = &value.token_restriction_id {
            builder.token_restriction_id(val);
        }
        Ok(builder.build()?)
    }
}

#[cfg(test)]
pub mod tests {

    use crate::entity::federated_mapping;

    use super::*;

    pub fn get_mapping_mock<I: Into<String>>(id: I) -> federated_mapping::Model {
        federated_mapping::Model {
            id: id.into(),
            name: "name".into(),
            domain_id: Some("did".into()),
            idp_id: "idp".into(),
            r#type: MappingType::default().into(),
            enabled: true,
            allowed_redirect_uris: None,
            user_id_claim: "sub".into(),
            user_name_claim: "preferred_username".into(),
            domain_id_claim: Some("domain_id".into()),
            groups_claim: None,
            bound_audiences: None,
            bound_subject: None,
            bound_claims: None,
            oidc_scopes: None,
            token_project_id: None,
            token_restriction_id: None,
        }
    }
}
