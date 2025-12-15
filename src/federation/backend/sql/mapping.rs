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

use crate::db::entity::{
    federated_mapping as db_federated_mapping, sea_orm_active_enums::MappingType as db_mapping_type,
};
use crate::federation::backend::error::FederationDatabaseError;
use crate::federation::types::*;

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

impl TryFrom<db_federated_mapping::Model> for Mapping {
    type Error = FederationDatabaseError;

    fn try_from(value: db_federated_mapping::Model) -> Result<Self, Self::Error> {
        let mut builder = MappingBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name.clone());
        builder.idp_id(value.idp_id.clone());
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
        builder.user_id_claim(value.user_id_claim.clone());
        builder.user_name_claim(value.user_name_claim.clone());
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
        if let Some(val) = &value.bound_claims {
            builder.bound_claims(val.clone());
        }
        if let Some(val) = &value.oidc_scopes
            && !val.is_empty()
        {
            builder.oidc_scopes(Vec::from_iter(val.split(",").map(Into::into)));
        }
        if let Some(val) = &value.token_project_id {
            builder.token_project_id(val.clone());
        }
        if let Some(val) = &value.token_restriction_id {
            builder.token_restriction_id(val.clone());
        }
        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {

    use crate::db::entity::federated_mapping;

    use super::*;

    pub(super) fn get_mapping_mock<S: AsRef<str>>(id: S) -> federated_mapping::Model {
        federated_mapping::Model {
            id: id.as_ref().into(),
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
