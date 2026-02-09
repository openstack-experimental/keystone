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

use crate::db::entity::id_mapping as db_id_mapping;
use crate::db::entity::sea_orm_active_enums::EntityType;
use crate::identity_mapping::types::{IdMapping, IdMappingEntityType};

mod get;

pub use get::*;

impl From<db_id_mapping::Model> for IdMapping {
    fn from(value: db_id_mapping::Model) -> Self {
        IdMapping {
            public_id: value.public_id.clone(),
            local_id: value.local_id.clone(),
            domain_id: value.domain_id.clone(),
            entity_type: value.entity_type.into(),
        }
    }
}

impl From<IdMappingEntityType> for EntityType {
    fn from(value: IdMappingEntityType) -> Self {
        match value {
            IdMappingEntityType::User => EntityType::User,
            IdMappingEntityType::Group => EntityType::Group,
        }
    }
}

impl From<EntityType> for IdMappingEntityType {
    fn from(value: EntityType) -> Self {
        match value {
            EntityType::User => IdMappingEntityType::User,
            EntityType::Group => IdMappingEntityType::Group,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;

    pub fn get_id_mapping_mock<P: Into<String>, L: Into<String>>(
        public_id: P,
        local_id: L,
    ) -> db_id_mapping::Model {
        db_id_mapping::Model {
            public_id: public_id.into(),
            local_id: local_id.into(),
            domain_id: "foo_domain".into(),
            entity_type: EntityType::User,
        }
    }
}
