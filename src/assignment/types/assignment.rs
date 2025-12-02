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
use std::fmt;
use validator::Validate;

/// The assignment object.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(strip_option, into))]
pub struct Assignment {
    /// The role ID.
    #[validate(length(max = 64))]
    pub role_id: String,
    /// The role name.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub role_name: Option<String>,
    /// The actor id.
    #[validate(length(max = 64))]
    pub actor_id: String,
    /// The target id.
    #[validate(length(max = 64))]
    pub target_id: String,
    /// The assignment type.
    pub r#type: AssignmentType,
    /// Inherited flag.
    pub inherited: bool,
}

/// Role assignment type.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum AssignmentType {
    /// Group to the domain.
    GroupDomain,
    /// Group to the project.
    GroupProject,
    /// User to the domain.
    UserDomain,
    /// User to the project.
    UserProject,
    /// User to the system.
    UserSystem,
    /// Group to the system.
    GroupSystem,
}

impl fmt::Display for AssignmentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::GroupDomain => write!(f, "GroupDomain"),
            Self::GroupProject => write!(f, "GroupProject"),
            Self::GroupSystem => write!(f, "GroupSystem"),
            Self::UserDomain => write!(f, "UserDomain"),
            Self::UserProject => write!(f, "UserProject"),
            Self::UserSystem => write!(f, "UserSystem"),
        }
    }
}

/// Parameters for listing role assignments for role/target/actor.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(strip_option, into))]
pub struct RoleAssignmentListParameters {
    /// Query role assignments filtering results by the role
    #[builder(default)]
    #[validate(length(max = 64))]
    pub role_id: Option<String>,

    /// Get role assignments for the user.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub user_id: Option<String>,

    /// Get role assignments for the group.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub group_id: Option<String>,

    /// Query role assignments on the project.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub project_id: Option<String>,
    /// Query role assignments on the domain.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,
    /// Query role assignments on the system.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub system: Option<String>,

    // #[builder(default)]
    // pub inherited: Option<bool>,
    /// Query the effective assignments, including any assignments gained by
    /// virtue of group membership.
    #[builder(default)]
    pub effective: Option<bool>,

    /// If set to true, then the names of any entities returned will be include
    /// as well as their IDs. Any value other than 0 (including no value)
    /// will be interpreted as true.
    #[builder(default)]
    pub include_names: Option<bool>,
}

/// Querying effective role assignments for list of actors (typically user with
/// all groups user is member of) on list of targets (exactl project + inherited
/// from uppoer projects/domain).
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[builder(setter(strip_option, into))]
pub struct RoleAssignmentListForMultipleActorTargetParameters {
    /// List of actors for which assignments are looked up.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub actors: Vec<String>,

    /// Optionally filter for the concrete role ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub role_id: Option<String>,

    /// List of targets for which assignments are looked up.
    #[builder(default)]
    #[validate(nested)]
    pub targets: Vec<RoleAssignmentTarget>,
}

/// Role assignment target which is either target_id or target_id with explicit
/// inherited parameter.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
pub struct RoleAssignmentTarget {
    /// The role assignment target ID.
    #[validate(length(max = 64))]
    pub id: String,
    /// The role assignment target type.
    pub r#type: RoleAssignmentTargetType,
    /// Specifies whether the target is only considered for inherited assignments.
    pub inherited: Option<bool>,
}

/// Role assignment target as Project(id), Domain(id) or System(id).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum RoleAssignmentTargetType {
    /// Project ID.
    Project,
    /// Domain ID.
    Domain,
    /// System ID.
    System,
}
