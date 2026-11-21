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

use openstack_keystone_core_types::assignment as provider_types;

use crate::error::KeystoneApiError;
use crate::v3::role_assignment as api_types;

impl TryFrom<provider_types::Assignment> for api_types::Assignment {
    type Error = KeystoneApiError;

    fn try_from(value: provider_types::Assignment) -> Result<Self, Self::Error> {
        let mut builder = api_types::AssignmentBuilder::default();
        builder.role(api_types::Role {
            id: value.role_id,
            name: value.role_name,
            links: None,
        });
        match value.r#type {
            provider_types::AssignmentType::GroupDomain => {
                builder.group(api_types::Group { id: value.actor_id });
                builder.scope(api_types::Scope::Domain(api_types::Domain {
                    id: value.target_id,
                }));
            }
            provider_types::AssignmentType::GroupProject => {
                builder.group(api_types::Group { id: value.actor_id });
                builder.scope(api_types::Scope::Project(api_types::Project {
                    id: value.target_id,
                }));
            }
            provider_types::AssignmentType::UserDomain => {
                builder.user(api_types::User { id: value.actor_id });
                builder.scope(api_types::Scope::Domain(api_types::Domain {
                    id: value.target_id,
                }));
            }
            provider_types::AssignmentType::UserProject => {
                builder.user(api_types::User { id: value.actor_id });
                builder.scope(api_types::Scope::Project(api_types::Project {
                    id: value.target_id,
                }));
            }
            provider_types::AssignmentType::UserSystem => {
                builder.user(api_types::User { id: value.actor_id });
                builder.scope(api_types::Scope::System(api_types::System {
                    id: value.target_id,
                }));
            }
            provider_types::AssignmentType::GroupSystem => {
                builder.group(api_types::Group { id: value.actor_id });
                builder.scope(api_types::Scope::System(api_types::System {
                    id: value.target_id,
                }));
            }
        }
        Ok(builder.build()?)
    }
}

impl TryFrom<api_types::RoleAssignmentListParameters>
    for provider_types::RoleAssignmentListParameters
{
    type Error = KeystoneApiError;

    fn try_from(value: api_types::RoleAssignmentListParameters) -> Result<Self, Self::Error> {
        let mut builder = provider_types::RoleAssignmentListParametersBuilder::default();
        // Parity with Python Keystone (`api/role_assignments.py`).
        if value.user_id.is_some() && value.group_id.is_some() {
            return Err(KeystoneApiError::BadRequest(
                "Specify a user or group, not both".into(),
            ));
        }
        if value.effective.is_some_and(|x| x) && value.group_id.is_some() {
            return Err(KeystoneApiError::BadRequest(
                "Combining effective and group filter will always result in an empty list".into(),
            ));
        }

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
        // The /role_assignments API always resolves implied roles.
        builder.resolve_implied_roles(true);
        Ok(builder.build()?)
    }
}

impl TryFrom<provider_types::Assignment> for api_types::Role {
    type Error = KeystoneApiError;

    fn try_from(value: provider_types::Assignment) -> Result<Self, Self::Error> {
        Ok(api_types::Role {
            id: value.role_id,
            name: value.role_name,
            links: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::v3::role_assignment::*;
    use openstack_keystone_core_types::assignment as provider_types;

    #[test]
    fn test_assignment_conversion() {
        assert_eq!(
            Assignment {
                role: Role {
                    id: "role".into(),
                    name: Some("role_name".into()),
                    links: None,
                },
                user: Some(User { id: "actor".into() }),
                scope: Scope::Project(Project {
                    id: "target".into()
                }),
                group: None,
            },
            Assignment::try_from(provider_types::Assignment {
                role_id: "role".into(),
                role_name: Some("role_name".into()),
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: provider_types::AssignmentType::UserProject,
                inherited: false,
                implied_via: None,
            })
            .unwrap()
        );
        assert_eq!(
            Assignment {
                role: Role {
                    id: "role".into(),
                    name: None,
                    links: None,
                },
                user: Some(User { id: "actor".into() }),
                scope: Scope::Domain(Domain {
                    id: "target".into()
                }),
                group: None,
            },
            Assignment::try_from(provider_types::Assignment {
                role_id: "role".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: provider_types::AssignmentType::UserDomain,
                inherited: false,
                implied_via: None,
            })
            .unwrap()
        );
        assert_eq!(
            Assignment {
                role: Role {
                    id: "role".into(),
                    name: None,
                    links: None,
                },
                group: Some(Group { id: "actor".into() }),
                scope: Scope::Project(Project {
                    id: "target".into()
                }),
                user: None,
            },
            Assignment::try_from(provider_types::Assignment {
                role_id: "role".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: provider_types::AssignmentType::GroupProject,
                inherited: false,
                implied_via: None,
            })
            .unwrap()
        );
        assert_eq!(
            Assignment {
                role: Role {
                    id: "role".into(),
                    name: None,
                    links: None,
                },
                group: Some(Group { id: "actor".into() }),
                scope: Scope::Domain(Domain {
                    id: "target".into()
                }),
                user: None,
            },
            Assignment::try_from(provider_types::Assignment {
                role_id: "role".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: provider_types::AssignmentType::GroupDomain,
                inherited: false,
                implied_via: None,
            })
            .unwrap()
        );
    }

    fn convert(
        params: RoleAssignmentListParameters,
    ) -> Result<provider_types::RoleAssignmentListParameters, crate::error::KeystoneApiError> {
        params.try_into()
    }

    #[test]
    fn test_list_parameters_user_and_group_rejected() {
        let res = convert(RoleAssignmentListParameters {
            user_id: Some("uid".into()),
            group_id: Some("gid".into()),
            ..Default::default()
        });
        assert!(matches!(
            res,
            Err(crate::error::KeystoneApiError::BadRequest(_))
        ));
    }

    #[test]
    fn test_list_parameters_effective_group_rejected() {
        let res = convert(RoleAssignmentListParameters {
            group_id: Some("gid".into()),
            effective: Some(true),
            ..Default::default()
        });
        assert!(matches!(
            res,
            Err(crate::error::KeystoneApiError::BadRequest(_))
        ));
    }

    #[test]
    fn test_list_parameters_valid_combinations() {
        let group = convert(RoleAssignmentListParameters {
            group_id: Some("gid".into()),
            effective: Some(false),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(group.group_id.as_deref(), Some("gid"));

        let group_no_effective = convert(RoleAssignmentListParameters {
            group_id: Some("gid".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(group_no_effective.group_id.as_deref(), Some("gid"));

        let user = convert(RoleAssignmentListParameters {
            user_id: Some("uid".into()),
            effective: Some(true),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(user.user_id.as_deref(), Some("uid"));
        assert_eq!(user.effective, Some(true));
    }
}
