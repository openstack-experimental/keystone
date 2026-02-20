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

pub use openstack_keystone_api_types::v3::role_assignment::*;

use crate::api::error::KeystoneApiError;
use crate::assignment::types;

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
                builder.group(Group { id: value.actor_id });
                builder.scope(Scope::Domain(Domain {
                    id: value.target_id,
                }));
            }
            types::AssignmentType::GroupProject => {
                builder.group(Group { id: value.actor_id });
                builder.scope(Scope::Project(Project {
                    id: value.target_id,
                }));
            }
            types::AssignmentType::UserDomain => {
                builder.user(User { id: value.actor_id });
                builder.scope(Scope::Domain(Domain {
                    id: value.target_id,
                }));
            }
            types::AssignmentType::UserProject => {
                builder.user(User { id: value.actor_id });
                builder.scope(Scope::Project(Project {
                    id: value.target_id,
                }));
            }
            types::AssignmentType::UserSystem => {
                builder.user(User { id: value.actor_id });
                builder.scope(Scope::System(System {
                    id: value.target_id,
                }));
            }
            types::AssignmentType::GroupSystem => {
                builder.group(Group { id: value.actor_id });
                builder.scope(Scope::System(System {
                    id: value.target_id,
                }));
            }
        }
        Ok(builder.build()?)
    }
}

impl TryFrom<RoleAssignmentListParameters> for types::RoleAssignmentListParameters {
    type Error = KeystoneApiError;

    fn try_from(value: RoleAssignmentListParameters) -> Result<Self, Self::Error> {
        let mut builder = types::RoleAssignmentListParametersBuilder::default();
        // Filter by role
        if let Some(val) = &value.role_id {
            builder.role_id(val);
        }

        // Filter by actor
        if let Some(val) = &value.user_id {
            builder.user_id(val);
        } else if let Some(val) = &value.group_id {
            builder.group_id(val);
        }

        // Filter by target
        if let Some(val) = &value.project_id {
            builder.project_id(val);
        } else if let Some(val) = &value.domain_id {
            builder.domain_id(val);
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
                implied_via: None,
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
                implied_via: None,
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
                implied_via: None,
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
                implied_via: None,
            })
            .unwrap()
        );
    }
}
