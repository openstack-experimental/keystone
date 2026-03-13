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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::BuilderError;

/// Id mapping entity.
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, Serialize, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct IdMapping {
    /// The domain_id the entity belongs to.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,
    /// The entity type.
    pub entity_type: IdMappingEntityType,
    /// The local ID of the entity.
    pub local_id: String,
    /// The public ID of the entity.
    pub public_id: String,
}

/// ID mapping entity type.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Serialize, PartialEq)]
pub enum IdMappingEntityType {
    /// Group.
    Group,
    /// User.
    User,
}
