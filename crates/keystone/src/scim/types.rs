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
//! # SCIM v2 `User` wire types (ADR 0024 §4)
//!
//! A pragmatic subset of RFC 7644's `User` resource — no `PATCH`-only
//! attributes, no complex multi-valued attribute constructs beyond a single
//! `emails` list. Attributes without a first-class Keystone `User` field
//! are namespaced under `extra["scim_*"]` per ADR 0024 §4's mapping table.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use openstack_keystone_core::identity::generate_public_id;
use openstack_keystone_core_types::identity::{
    Group, GroupCreate, GroupUpdate, UserCreate, UserResponse, UserType, UserUpdate,
};
use openstack_keystone_core_types::scim::ScimResourceIndex;

/// `urn:ietf:params:scim:schemas:core:2.0:User` schema URI.
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// `urn:ietf:params:scim:schemas:core:2.0:Group` schema URI.
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// `urn:ietf:params:scim:api:messages:2.0:ListResponse` schema URI.
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
/// ADR 0024 §11 membership-graph-bomb cap: max `members` entries per request.
pub const MAX_GROUP_MEMBERS: usize = 1000;

pub(crate) const EXTRA_GIVEN_NAME: &str = "scim_given_name";
pub(crate) const EXTRA_FAMILY_NAME: &str = "scim_family_name";
pub(crate) const EXTRA_DISPLAY_NAME: &str = "scim_display_name";
const EXTRA_PRIMARY_EMAIL: &str = "scim_primary_email";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

impl ScimName {
    fn is_empty(&self) -> bool {
        self.given_name.is_none() && self.family_name.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: String,
    pub location: String,
    pub created: String,
    pub last_modified: String,
}

/// `GET`/`POST`/`PUT` response representation of a SCIM `User`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    pub active: bool,
    pub meta: ScimMeta,
}

impl ScimUser {
    /// Build the wire representation from the core Identity record plus its
    /// SCIM ownership anchor. `location` is the pre-built absolute
    /// `meta.location` URL (RFC 7644 §3.1) -- built by the caller via
    /// [`crate::scim::location::resource_location`] so this module stays
    /// free of config/I-O concerns.
    pub fn from_domain(user: &UserResponse, index: &ScimResourceIndex, location: String) -> Self {
        let given_name = extra_str(&user.extra, EXTRA_GIVEN_NAME);
        let family_name = extra_str(&user.extra, EXTRA_FAMILY_NAME);
        let name = if given_name.is_some() || family_name.is_some() {
            Some(ScimName {
                given_name,
                family_name,
            })
        } else {
            None
        };
        let emails = extra_str(&user.extra, EXTRA_PRIMARY_EMAIL)
            .map(|value| {
                vec![ScimEmail {
                    value,
                    primary: true,
                }]
            })
            .unwrap_or_default();

        Self {
            schemas: vec![USER_SCHEMA.to_string()],
            id: user.id.clone(),
            external_id: index.external_id.clone(),
            user_name: user.name.clone(),
            name,
            display_name: extra_str(&user.extra, EXTRA_DISPLAY_NAME),
            emails,
            active: user.enabled,
            meta: ScimMeta {
                resource_type: "User".to_string(),
                location,
                created: epoch_to_rfc3339(index.created_at),
                last_modified: epoch_to_rfc3339(index.updated_at),
            },
        }
    }
}

/// `POST`/`PUT` request body — also used for `PUT` full-replace (ADR 0024
/// PR2 scope: no `PATCH`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserWrite {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(default)]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(default)]
    pub name: Option<ScimName>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool {
    true
}

impl ScimUserWrite {
    /// Rejects a request whose `schemas` array is missing or doesn't
    /// declare the core `User` schema (RFC 7644 §3.3).
    pub fn validate_schemas(&self) -> Result<(), String> {
        if self.schemas.iter().any(|s| s == USER_SCHEMA) {
            Ok(())
        } else {
            Err(format!("schemas must include `{USER_SCHEMA}`"))
        }
    }

    fn extra(&self) -> HashMap<String, Value> {
        let mut extra = HashMap::new();
        if let Some(name) = &self.name
            && !name.is_empty()
        {
            if let Some(gn) = &name.given_name {
                extra.insert(EXTRA_GIVEN_NAME.to_string(), Value::String(gn.clone()));
            }
            if let Some(fname) = &name.family_name {
                extra.insert(EXTRA_FAMILY_NAME.to_string(), Value::String(fname.clone()));
            }
        }
        if let Some(display_name) = &self.display_name {
            extra.insert(
                EXTRA_DISPLAY_NAME.to_string(),
                Value::String(display_name.clone()),
            );
        }
        if let Some(email) = self
            .emails
            .iter()
            .find(|e| e.primary)
            .or_else(|| self.emails.first())
        {
            extra.insert(
                EXTRA_PRIMARY_EMAIL.to_string(),
                Value::String(email.value.clone()),
            );
        }
        extra
    }

    /// Convert to a core Identity `UserCreate` (ADR 0024 §4 attribute
    /// mapping). The user's `id` is derived deterministically from
    /// `(domain_id, external_id, "user")` via the same sha256 formula
    /// python-keystone uses for federation shadow users — this is what lets
    /// a later federated login with the same IdP `sub` claim converge on
    /// this same user instead of creating a duplicate (see ADR 0024 dedup
    /// fix). The user is created as `NonLocal` (no password, no
    /// `local_user` row) since SCIM-provisioned identities are always
    /// externally managed.
    pub fn to_user_create(&self, domain_id: &str, external_id: &str) -> UserCreate {
        UserCreate {
            default_project_id: None,
            domain_id: Some(domain_id.to_string()),
            enabled: Some(self.active),
            extra: self.extra(),
            federated: None,
            id: Some(generate_public_id(domain_id, external_id, "user")),
            name: self.user_name.clone(),
            options: None,
            password: None,
            user_type: UserType::NonLocal,
        }
    }

    /// Convert to a core Identity `UserUpdate` (full-replace `PUT`).
    pub fn to_user_update(&self) -> UserUpdate {
        UserUpdate {
            default_project_id: None,
            enabled: Some(self.active),
            extra: self.extra(),
            federated: None,
            name: Some(self.user_name.clone()),
            options: None,
            password: None,
        }
    }
}

/// `GET /Users` list response envelope.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse {
    pub schemas: Vec<String>,
    pub total_results: usize,
    pub start_index: usize,
    pub items_per_page: usize,
    pub resources: Vec<ScimUser>,
}

/// A single `members` entry — RFC 7644 permits `display`/`$ref`/`type` too,
/// but ADR 0024 §4's Group mapping table only requires the member `User.id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupMember {
    pub value: String,
}

/// `GET`/`POST`/`PUT` response representation of a SCIM `Group`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimGroupMember>,
    pub meta: ScimMeta,
}

impl ScimGroup {
    /// Build the wire representation from the core Identity record, its SCIM
    /// ownership anchor, and its resolved membership (ADR 0024 §4, §7).
    /// `location` is the pre-built absolute `meta.location` URL (RFC 7644
    /// §3.1) -- see [`ScimUser::from_domain`]'s doc comment.
    pub fn from_domain(
        group: &Group,
        index: &ScimResourceIndex,
        member_ids: &[String],
        location: String,
    ) -> Self {
        Self {
            schemas: vec![GROUP_SCHEMA.to_string()],
            id: group.id.clone(),
            external_id: index.external_id.clone(),
            display_name: group.name.clone(),
            members: member_ids
                .iter()
                .map(|id| ScimGroupMember { value: id.clone() })
                .collect(),
            meta: ScimMeta {
                resource_type: "Group".to_string(),
                location,
                created: epoch_to_rfc3339(index.created_at),
                last_modified: epoch_to_rfc3339(index.updated_at),
            },
        }
    }
}

/// `POST`/`PUT` request body — also used for `PUT` full-replace (ADR 0024
/// PR3 scope: no `PATCH`). Unlike `User`, a SCIM `Group`'s `id` stays
/// server-assigned: nothing federates in *as* a Group, so there is no
/// convergence hazard for a deterministic id to solve (see the SCIM Users
/// identity-convergence note in `to_user_create`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupWrite {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(default)]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<ScimGroupMember>,
}

impl ScimGroupWrite {
    /// Rejects a request whose `schemas` array is missing or doesn't
    /// declare the core `Group` schema (RFC 7644 §3.3).
    pub fn validate_schemas(&self) -> Result<(), String> {
        if self.schemas.iter().any(|s| s == GROUP_SCHEMA) {
            Ok(())
        } else {
            Err(format!("schemas must include `{GROUP_SCHEMA}`"))
        }
    }

    /// The member `User.id`s this write requests, in request order.
    pub fn member_ids(&self) -> Vec<String> {
        self.members.iter().map(|m| m.value.clone()).collect()
    }

    /// Convert to a core Identity `GroupCreate` (ADR 0024 §4 attribute
    /// mapping). `externalId` is excluded — it lives only in
    /// `ScimResourceIndex.external_id`, never on the `Group` itself.
    pub fn to_group_create(&self, domain_id: &str) -> GroupCreate {
        GroupCreate {
            id: None,
            domain_id: domain_id.to_string(),
            name: self.display_name.clone(),
            description: None,
            extra: HashMap::new(),
        }
    }

    /// Convert to a core Identity `GroupUpdate` (full-replace `PUT`).
    pub fn to_group_update(&self) -> GroupUpdate {
        GroupUpdate {
            name: Some(self.display_name.clone()),
            description: None,
            extra: HashMap::new(),
        }
    }
}

/// `GET /Groups` list response envelope.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupListResponse {
    pub schemas: Vec<String>,
    pub total_results: usize,
    pub start_index: usize,
    pub items_per_page: usize,
    pub resources: Vec<ScimGroup>,
}

pub(crate) fn extra_str(extra: &HashMap<String, Value>, key: &str) -> Option<String> {
    extra.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn epoch_to_rfc3339(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}
