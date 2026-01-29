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
//! SQL driver data types.

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

use crate::error::BuilderError;
use crate::identity::types::*;

#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct User {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their
    /// default project, the default project is ignored at token creation.
    /// Additionally, if your default project is not valid, a token
    /// is issued without an explicit scope of authorization.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub default_project_id: Option<String>,

    /// The ID of the domain.
    #[validate(length(max = 64))]
    pub domain_id: String,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    pub enabled: bool,

    /// Additional user properties.
    #[builder(default)]
    pub extra: Option<Value>,

    /// The user ID.
    #[validate(length(max = 64))]
    pub id: String,

    /// The options for the user.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<UserOptions>,

    /// User type specific data.
    #[validate(nested)]
    pub type_data: UserType,
}

/// Data that is present on the existing local user.
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct LocalUserData {
    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    pub name: String,

    #[builder(default)]
    pub password_expires_at: Option<DateTime<Utc>>,

    /// User password.
    #[builder(default)]
    #[validate(length(max = 72))]
    pub password: Option<String>,
}

/// Federated user data.
#[derive(Builder, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct FederatedUserData {
    /// List of federated objects associated with a user. Each object in the
    /// list contains the `idp_id` and `protocols`. `protocols` is a list of
    /// objects, each of which contains `protocol_id` and `unique_id` of the
    /// protocol and user respectively.
    #[builder(default)]
    #[validate(nested)]
    pub data: Vec<Federation>,
}

/// Data that is present on the nonlocal user.
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct NonLocalUserData {
    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    pub name: String,
}

/// Data that is present on the service account user.
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ServiceAccountData {
    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    pub name: String,
}

/// User federation data.
#[derive(Builder, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Federation {
    /// Identity provider ID.
    #[validate(length(max = 64))]
    pub idp_id: String,

    /// Federated user name.
    #[validate(length(max = 255))]
    pub name: String,

    /// Protocols.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub protocol_ids: Vec<String>,

    /// Unique ID of the user within the IdP.
    #[builder]
    pub unique_id: String,
}

/// User type.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum UserType {
    /// Federated users only (authenticated via external IdP).
    Federated(FederatedUserData),

    /// Local users only (with passwords).
    Local(LocalUserData),

    /// Non-local users (users without local authentication).
    NonLocal(NonLocalUserData),

    /// Service Accounts (bots, etc).
    ServiceAccount(ServiceAccountData),
}

impl Validate for UserType {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Self::Federated(data) => data.validate(),
            Self::Local(data) => data.validate(),
            Self::NonLocal(data) => data.validate(),
            Self::ServiceAccount(data) => data.validate(),
        }
    }
}

impl TryFrom<UserCreate> for User {
    type Error = BuilderError;

    fn try_from(value: UserCreate) -> Result<Self, Self::Error> {
        let mut builder = UserBuilder::default();
        if let Some(val) = value.default_project_id {
            builder.default_project_id(val);
        }
        builder.domain_id(value.domain_id);
        builder.enabled(value.enabled.unwrap_or(true));
        if let Some(val) = value.extra {
            builder.extra(val);
        }
        if let Some(val) = &value.options {
            builder.options(val.clone());
        }
        builder.id(value
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string()));
        if let Some(fed) = value.federated {
            builder.type_data(UserType::Federated(FederatedUserData {
                data: fed
                    .into_iter()
                    .map(|f| Federation {
                        idp_id: f.idp_id,
                        name: value.name.clone(),
                        protocol_ids: f.protocols.into_iter().map(|p| p.protocol_id).collect(),
                        unique_id: f.unique_id,
                    })
                    .collect(),
            }));
        } else if let Some(opts) = &value.options
            && opts.is_service_account.is_some_and(|x| x)
        {
            builder.type_data(UserType::ServiceAccount(ServiceAccountData {
                name: value.name,
            }));
        } else {
            let mut data = LocalUserDataBuilder::default();
            data.name(value.name);
            if let Some(val) = value.password {
                data.password(val);
            }
            builder.type_data(UserType::Local(data.build()?));
        }
        builder.build()
    }
}

impl TryFrom<ServiceAccountCreate> for User {
    type Error = BuilderError;

    fn try_from(value: ServiceAccountCreate) -> Result<Self, Self::Error> {
        let mut builder = UserBuilder::default();
        builder.domain_id(value.domain_id);
        builder.enabled(value.enabled.unwrap_or(true));
        builder.id(value
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string()));
        builder.type_data(UserType::ServiceAccount(ServiceAccountData {
            name: value.name,
        }));
        builder.build()
    }
}
