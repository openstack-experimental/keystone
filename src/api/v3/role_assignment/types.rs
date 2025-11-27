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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::api::error::KeystoneApiError;
use crate::assignment::types;

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct Assignment {
    /// Role ID
    pub role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub user: Option<User>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub group: Option<Group>,
    pub scope: Scope,
}

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Role {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct User {
    pub id: String,
}

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Group {
    pub id: String,
}

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Project {
    pub id: String,
}

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Domain {
    pub id: String,
}

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct System {
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Project(Project),
    Domain(Domain),
    System(System),
}

impl TryFrom<types::Assignment> for Assignment {
    type Error = KeystoneApiError;

    fn try_from(value: types::Assignment) -> Result<Self, Self::Error> {
        let mut builder = AssignmentBuilder::default();
        builder.role(Role {
            id: value.role_id,
            name: value.role_name,
        });
        match value.r#type {
            types::AssignmentType::GroupDomain => {
                builder.group(Group {
                    id: value.actor_id.clone(),
                });
                builder.scope(Scope::Domain(Domain {
                    id: value.target_id.clone(),
                }));
            }
            types::AssignmentType::GroupProject => {
                builder.group(Group {
                    id: value.actor_id.clone(),
                });
                builder.scope(Scope::Project(Project {
                    id: value.target_id.clone(),
                }));
            }
            types::AssignmentType::UserDomain => {
                builder.user(User {
                    id: value.actor_id.clone(),
                });
                builder.scope(Scope::Domain(Domain {
                    id: value.target_id.clone(),
                }));
            }
            types::AssignmentType::UserProject => {
                builder.user(User {
                    id: value.actor_id.clone(),
                });
                builder.scope(Scope::Project(Project {
                    id: value.target_id.clone(),
                }));
            }
            types::AssignmentType::UserSystem => {
                builder.user(User {
                    id: value.actor_id.clone(),
                });
                builder.scope(Scope::System(System {
                    id: value.target_id.clone(),
                }));
            }
            types::AssignmentType::GroupSystem => {
                builder.group(Group {
                    id: value.actor_id.clone(),
                });
                builder.scope(Scope::System(System {
                    id: value.target_id.clone(),
                }));
            }
        }
        Ok(builder.build()?)
    }
}

impl From<AssignmentBuilderError> for KeystoneApiError {
    fn from(err: AssignmentBuilderError) -> Self {
        Self::InternalError(err.to_string())
    }
}

impl From<types::RoleAssignmentListParametersBuilderError> for KeystoneApiError {
    fn from(err: types::RoleAssignmentListParametersBuilderError) -> Self {
        Self::InternalError(err.to_string())
    }
}

/// Assignments
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AssignmentList {
    /// Collection of role assignment objects
    pub role_assignments: Vec<Assignment>,
}

impl IntoResponse for AssignmentList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// List role assignments query parameters
#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct RoleAssignmentListParameters {
    /// Filters the response by a domain ID.
    #[serde(rename = "scope.domain.id")]
    pub domain_id: Option<String>,

    /// Filters the response by a group ID.
    #[serde(rename = "group.id")]
    pub group_id: Option<String>,

    /// Returns the effective assignments, including any assignments gained by
    /// virtue of group membership.
    pub effective: Option<bool>,

    /// Filters the response by a project ID.
    #[serde(rename = "scope.project.id")]
    pub project_id: Option<String>,

    /// Filters the response by a role ID.
    #[serde(rename = "role.id")]
    pub role_id: Option<String>,

    /// Filters the response by a user ID.
    #[serde(rename = "user.id")]
    pub user_id: Option<String>,

    /// If set to true, then the names of any entities returned will be include
    /// as well as their IDs. Any value other than 0 (including no value)
    /// will be interpreted as true.
    ///
    /// New in version 3.6
    #[serde(default)]
    pub include_names: Option<bool>,
}

impl TryFrom<RoleAssignmentListParameters> for types::RoleAssignmentListParameters {
    type Error = KeystoneApiError;

    fn try_from(value: RoleAssignmentListParameters) -> Result<Self, Self::Error> {
        let mut builder = types::RoleAssignmentListParametersBuilder::default();
        // Filter by role
        if let Some(val) = &value.role_id {
            builder.role_id(val.clone());
        }

        // Filter by actor
        if let Some(val) = &value.user_id {
            builder.user_id(val.clone());
        } else if let Some(val) = &value.group_id {
            builder.group_id(val.clone());
        }

        // Filter by target
        if let Some(val) = &value.project_id {
            builder.project_id(val.clone());
        } else if let Some(val) = &value.domain_id {
            builder.domain_id(val.clone());
        }

        if let Some(val) = value.effective {
            builder.effective(val);
        }
        if let Some(val) = value.include_names {
            builder.include_names(val);
        }
        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assignment::types;

    #[test]
    fn test_assignment_conversion() {
        assert_eq!(
            Assignment {
                role: Role {
                    id: "role".into(),
                    name: Some("role_name".into())
                },
                user: Some(User { id: "actor".into() }),
                scope: Scope::Project(Project {
                    id: "target".into()
                }),
                group: None,
            },
            Assignment::try_from(types::Assignment {
                role_id: "role".into(),
                role_name: Some("role_name".into()),
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: types::AssignmentType::UserProject,
                inherited: false,
            })
            .unwrap()
        );
        assert_eq!(
            Assignment {
                role: Role {
                    id: "role".into(),
                    name: None
                },
                user: Some(User { id: "actor".into() }),
                scope: Scope::Domain(Domain {
                    id: "target".into()
                }),
                group: None,
            },
            Assignment::try_from(types::Assignment {
                role_id: "role".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: types::AssignmentType::UserDomain,
                inherited: false,
            })
            .unwrap()
        );
        assert_eq!(
            Assignment {
                role: Role {
                    id: "role".into(),
                    name: None
                },
                group: Some(Group { id: "actor".into() }),
                scope: Scope::Project(Project {
                    id: "target".into()
                }),
                user: None,
            },
            Assignment::try_from(types::Assignment {
                role_id: "role".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: types::AssignmentType::GroupProject,
                inherited: false,
            })
            .unwrap()
        );
        assert_eq!(
            Assignment {
                role: Role {
                    id: "role".into(),
                    name: None
                },
                group: Some(Group { id: "actor".into() }),
                scope: Scope::Domain(Domain {
                    id: "target".into()
                }),
                user: None,
            },
            Assignment::try_from(types::Assignment {
                role_id: "role".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: types::AssignmentType::GroupDomain,
                inherited: false,
            })
            .unwrap()
        );
    }
}
