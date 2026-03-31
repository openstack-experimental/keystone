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
use std::fmt;

use openstack_keystone_core::auth::ExecutionContext;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use openstack_keystone_core::assignment::AssignmentProviderError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::assignment::*;
use openstack_keystone_core_types::idmapping::*;

#[derive(Debug)]
pub(crate) enum OpenFGAUser {
    User(Actor),
    Group(Actor),
}

impl fmt::Display for OpenFGAUser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::User(x) => write!(f, "{}", x.openfga_id),
            Self::Group(x) => write!(f, "{}", x.openfga_id),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Actor {
    pub(crate) openfga_id: String,
    pub(crate) local_id: String,
}

impl OpenFGAUser {
    pub(crate) fn local_actor_id(&self) -> String {
        match self {
            Self::User(x) => x.local_id.clone(),
            Self::Group(x) => x.local_id.clone(),
        }
    }

    pub(crate) async fn from_assignment(
        state: &ServiceState,
        assignment: &Assignment,
    ) -> Result<Self, OpenFGADriverError> {
        match assignment.r#type {
            AssignmentType::UserProject
            | AssignmentType::UserDomain
            | AssignmentType::UserSystem => Self::from_user(state, &assignment.actor_id).await,
            AssignmentType::GroupProject
            | AssignmentType::GroupDomain
            | AssignmentType::GroupSystem => Self::from_group(state, &assignment.actor_id).await,
        }
    }

    pub(crate) async fn from_create_assignment(
        state: &ServiceState,
        assignment: &AssignmentCreate,
    ) -> Result<Self, OpenFGADriverError> {
        match assignment.r#type {
            AssignmentType::UserProject
            | AssignmentType::UserDomain
            | AssignmentType::UserSystem => Self::from_user(state, &assignment.actor_id).await,
            AssignmentType::GroupProject
            | AssignmentType::GroupDomain
            | AssignmentType::GroupSystem => Self::from_group(state, &assignment.actor_id).await,
        }
    }

    pub(crate) async fn from_user(
        state: &ServiceState,
        user_id: &String,
    ) -> Result<Self, OpenFGADriverError> {
        let ctx = ExecutionContext::internal(state);
        let user_domain_id = state
            .provider
            .get_identity_provider()
            .get_user_domain_id(&ctx, user_id)
            .await?;
        let user_mapping = state
            .provider
            .get_idmapping_provider()
            .get_by_local_id(&ctx, user_id, &user_domain_id, IdMappingEntityType::User)
            .await?;
        Ok(Self::User(Actor {
            openfga_id: user_mapping
                .map(|x| x.public_id)
                .unwrap_or_else(|| format!("user:{}", user_id)),
            local_id: user_id.clone(),
        }))
    }

    pub(crate) async fn from_group(
        state: &ServiceState,
        group_id: &String,
    ) -> Result<Self, OpenFGADriverError> {
        let ctx = ExecutionContext::internal(state);
        let group_domain = state
            .provider
            .get_identity_provider()
            .get_group(&ctx, group_id)
            .await?
            .ok_or(OpenFGADriverError::GroupNotFound(group_id.clone()))?;
        let group_mapping = state
            .provider
            .get_idmapping_provider()
            .get_by_local_id(&ctx, group_id, &group_domain.id, IdMappingEntityType::Group)
            .await?;
        Ok(Self::Group(Actor {
            openfga_id: group_mapping
                .map(|x| x.public_id)
                .unwrap_or_else(|| format!("group:{}", group_id)),
            local_id: group_id.clone(),
        }))
    }

    pub(crate) async fn from_list_parameters(
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Option<Self>, OpenFGADriverError> {
        if let Some(user_id) = &params.user_id {
            Ok(Some(Self::from_user(state, user_id).await?))
        } else if let Some(group_id) = &params.group_id {
            Ok(Some(Self::from_group(state, group_id).await?))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn as_assignment_type(&self, object: &OpenFGAObject) -> AssignmentType {
        match (self, object) {
            (OpenFGAUser::User(_), OpenFGAObject::Domain(_)) => AssignmentType::UserDomain,
            (OpenFGAUser::User(_), OpenFGAObject::Project(_)) => AssignmentType::UserProject,
            (OpenFGAUser::User(_), OpenFGAObject::System(_)) => AssignmentType::UserSystem,
            (OpenFGAUser::Group(_), OpenFGAObject::Domain(_)) => AssignmentType::GroupDomain,
            (OpenFGAUser::Group(_), OpenFGAObject::Project(_)) => AssignmentType::GroupProject,
            (OpenFGAUser::Group(_), OpenFGAObject::System(_)) => AssignmentType::GroupSystem,
        }
    }

    pub(crate) async fn from_openfga_tuple(
        state: &ServiceState,
        tuple: &OpenFGATuple,
    ) -> Result<Self, OpenFGADriverError> {
        let ctx = ExecutionContext::internal(state);
        if let Some(mapping) = state
            .provider
            .get_idmapping_provider()
            .get_by_public_id(&ctx, &tuple.user)
            .await?
        {
            let actor = Actor {
                openfga_id: tuple.user.clone(),
                local_id: mapping.local_id.clone(),
            };
            match &mapping.entity_type {
                IdMappingEntityType::User => Ok(Self::User(actor)),
                IdMappingEntityType::Group => Ok(Self::Group(actor)),
            }
        } else {
            Err(OpenFGADriverError::UnknownActor(tuple.user.clone()))
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum OpenFGAObject {
    Domain(String),
    Project(String),
    System(String),
}

impl OpenFGAObject {
    pub(crate) fn local_target_id(&self) -> String {
        match self {
            Self::Domain(x) => x.clone(),
            Self::Project(x) => x.clone(),
            Self::System(x) => x.clone(),
        }
    }
}

impl fmt::Display for OpenFGAObject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Domain(x) => write!(f, "domain:{}", x),
            Self::Project(x) => write!(f, "project:{}", x),
            Self::System(x) => write!(f, "system:{}", x),
        }
    }
}

impl From<&Assignment> for OpenFGAObject {
    fn from(value: &Assignment) -> Self {
        match value.r#type {
            AssignmentType::GroupDomain => Self::Domain(value.target_id.clone()),
            AssignmentType::GroupProject => Self::Project(value.target_id.clone()),
            AssignmentType::GroupSystem => Self::System(value.target_id.clone()),
            AssignmentType::UserDomain => Self::Domain(value.target_id.clone()),
            AssignmentType::UserProject => Self::Project(value.target_id.clone()),
            AssignmentType::UserSystem => Self::System(value.target_id.clone()),
        }
    }
}
impl From<&AssignmentCreate> for OpenFGAObject {
    fn from(value: &AssignmentCreate) -> Self {
        match value.r#type {
            AssignmentType::GroupDomain => Self::Domain(value.target_id.clone()),
            AssignmentType::GroupProject => Self::Project(value.target_id.clone()),
            AssignmentType::GroupSystem => Self::System(value.target_id.clone()),
            AssignmentType::UserDomain => Self::Domain(value.target_id.clone()),
            AssignmentType::UserProject => Self::Project(value.target_id.clone()),
            AssignmentType::UserSystem => Self::System(value.target_id.clone()),
        }
    }
}

impl TryFrom<&RoleAssignmentListParameters> for OpenFGAObject {
    type Error = OpenFGADriverError;
    fn try_from(value: &RoleAssignmentListParameters) -> Result<Self, Self::Error> {
        if let Some(project_id) = &value.project_id {
            Ok(Self::Project(project_id.clone()))
        } else if let Some(domain_id) = &value.domain_id {
            Ok(Self::Domain(domain_id.clone()))
        } else if let Some(system_id) = &value.system_id {
            Ok(Self::System(system_id.clone()))
        } else {
            Err(Self::Error::NotOpenFGAObject)
        }
    }
}

impl TryFrom<&OpenFGATuple> for OpenFGAObject {
    type Error = OpenFGADriverError;
    fn try_from(value: &OpenFGATuple) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.object.split(':').collect();
        match parts.as_slice() {
            ["project", id] => {
                if !id.is_empty() {
                    Ok(Self::Project(id.to_string()))
                } else {
                    Err(OpenFGADriverError::NotSupportedOpenFGAObject(
                        value.object.clone(),
                    ))
                }
            }
            ["domain", id] => {
                if !id.is_empty() {
                    Ok(Self::Domain(id.to_string()))
                } else {
                    Err(OpenFGADriverError::NotSupportedOpenFGAObject(
                        value.object.clone(),
                    ))
                }
            }
            ["system", id] => {
                if !id.is_empty() {
                    Ok(Self::System(id.to_string()))
                } else {
                    Err(OpenFGADriverError::NotSupportedOpenFGAObject(
                        value.object.clone(),
                    ))
                }
            }
            _ => Err(OpenFGADriverError::NotSupportedOpenFGAObject(
                value.object.clone(),
            )),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGACheckResponse {
    pub(crate) allowed: bool,
    pub(crate) resolution: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGABatchCheckResponse {
    pub(crate) result: HashMap<String, OpenFGACheckResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGAErrorResponse {
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGAReadResponse {
    pub(crate) tuples: Vec<OpenFGATupleKey>,
    pub(crate) continuation_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGATupleKey {
    #[serde(rename = "key")]
    pub(crate) tuple: OpenFGATuple,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OpenFGATuple {
    pub(crate) user: String,
    pub(crate) relation: String,
    pub(crate) object: String,
}

/// Assignment provider error.
#[derive(Error, Debug)]
pub enum OpenFGADriverError {
    /// Group not found.
    #[error("group {0} not found")]
    GroupNotFound(String),

    /// Missing configuration for the openfga driver.
    #[error("openfga driver configuration missing")]
    MissingConfiguration,

    /// OpenFGA tuple references an actor unknown to the identity mapping
    /// provider (stale or external identity).
    #[error("cannot map openfga actor `{0}` to a known keystone identity")]
    UnknownActor(String),

    /// Identity mapping provider error.
    #[error(transparent)]
    IdentityMappingProvider {
        #[from]
        source: openstack_keystone_core::idmapping::IdMappingProviderError,
    },

    /// Identity provider error.
    #[error(transparent)]
    IdentityProvider {
        #[from]
        source: openstack_keystone_core::identity::IdentityProviderError,
    },

    /// Listing assignments knowing only the role is not supported.
    #[error("listing assignments by only the role is not supported by the openfga")]
    ListingAssignmentsByRoleNotSupported,

    /// Listing assignments without parameters is not supported.
    #[error("listing all assignments is not supported by the openfga")]
    ListingAllAssignmentsNotSupported,

    /// OpenFGA error.
    #[error("openfga http error: {0}")]
    OpenFGAError(String),

    #[error("cannot identify openfga object from known parameters")]
    NotOpenFGAObject,

    #[error("cannot map openfga object ({0}) to the keystone scope")]
    NotSupportedOpenFGAObject(String),

    /// (de)serialize error.
    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Reqwest error.
    #[error(transparent)]
    Reqwest {
        #[from]
        source: reqwest::Error,
    },

    /// Role mapping not configured.
    #[error("role to relation mapping for the openfga driver is not configured for role `{0}`")]
    RoleRelationNotConfigured(String),

    /// Url parsing error.
    #[error(transparent)]
    Url {
        #[from]
        source: url::ParseError,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: openstack_keystone_core::error::BuilderError,
    },
}

impl From<OpenFGADriverError> for AssignmentProviderError {
    fn from(source: OpenFGADriverError) -> Self {
        Self::Driver(source.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_from_tuple() {
        assert_eq!(
            OpenFGAObject::Project("pid".into()),
            OpenFGAObject::try_from(&OpenFGATuple {
                user: "uid".into(),
                relation: "rid".into(),
                object: "project:pid".into()
            })
            .unwrap()
        );
        assert_eq!(
            OpenFGAObject::Domain("did".into()),
            OpenFGAObject::try_from(&OpenFGATuple {
                user: "uid".into(),
                relation: "rid".into(),
                object: "domain:did".into()
            })
            .unwrap()
        );
        assert_eq!(
            OpenFGAObject::System("sid".into()),
            OpenFGAObject::try_from(&OpenFGATuple {
                user: "uid".into(),
                relation: "rid".into(),
                object: "system:sid".into()
            })
            .unwrap()
        );
        assert!(
            OpenFGAObject::try_from(&OpenFGATuple {
                user: "uid".into(),
                relation: "rid".into(),
                object: "project:".into()
            })
            .is_err()
        );
        assert!(
            OpenFGAObject::try_from(&OpenFGATuple {
                user: "uid".into(),
                relation: "rid".into(),
                object: "domain:".into()
            })
            .is_err()
        );
        assert!(
            OpenFGAObject::try_from(&OpenFGATuple {
                user: "uid".into(),
                relation: "rid".into(),
                object: "system:".into()
            })
            .is_err()
        );
        assert!(
            OpenFGAObject::try_from(&OpenFGATuple {
                user: "uid".into(),
                relation: "rid".into(),
                object: "wrong:".into()
            })
            .is_err()
        );
    }

    #[test]
    fn test_object_from_list_parameters() {
        assert_eq!(
            OpenFGAObject::Project("id".into()),
            OpenFGAObject::try_from(
                &RoleAssignmentListParametersBuilder::default()
                    .project_id("id")
                    .build()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            OpenFGAObject::Domain("id".into()),
            OpenFGAObject::try_from(
                &RoleAssignmentListParametersBuilder::default()
                    .domain_id("id")
                    .build()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            OpenFGAObject::System("id".into()),
            OpenFGAObject::try_from(
                &RoleAssignmentListParametersBuilder::default()
                    .system_id("id")
                    .build()
                    .unwrap()
            )
            .unwrap()
        );
        assert!(
            OpenFGAObject::try_from(
                &RoleAssignmentListParametersBuilder::default()
                    .build()
                    .unwrap()
            )
            .is_err()
        );
    }
}
