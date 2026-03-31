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

use serde::Deserialize;
use url::Url;

use crate::common::default_sql_driver;
use crate::pagination::ListLimitConfig;

/// Assignment Provider.
#[derive(Debug, Deserialize, Clone)]
pub struct AssignmentProvider {
    /// Assignment provider driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// `GET /v3/role_assignments` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,
}

impl Default for AssignmentProvider {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
            list_limit: ListLimitConfig::default(),
        }
    }
}

fn default_user_actor_types() -> Vec<String> {
    vec!["user".to_string()]
}
fn default_group_actor_types() -> Vec<String> {
    vec!["group".to_string()]
}
fn default_project_target_types() -> Vec<String> {
    vec!["project".to_string()]
}
fn default_domain_target_types() -> Vec<String> {
    vec!["domain".to_string()]
}
fn default_system_target_types() -> Vec<String> {
    vec!["system".to_string()]
}
fn default_retry_backoff_ms() -> u64 {
    100
}
fn default_max_concurrency() -> usize {
    10
}

/// Transform applied between Keystone entity ids and OpenFGA object ids.
///
/// Applied to every kind (actors and targets alike).
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OpenFGAIdTransform {
    /// The Keystone id is used verbatim as the OpenFGA object id.
    #[default]
    None,
    /// Keystone stores dashless UUIDs; OpenFGA stores them dashed. The
    /// Keystone -> OpenFGA direction inserts canonical `8-4-4-4-12` dashes
    /// into 32-hex ids, the reverse strips every `-`. Non-hex ids (`default`,
    /// `all`, ...) pass through unchanged in both directions.
    UuidDashes,
}

/// OpenFGA assignment driver.
///
/// Keystone entities are mapped onto OpenFGA objects purely from this
/// configuration - no per-entity lookup or reverse-mapping store. Each kind
/// (`user`, `group`, `project`, `domain`, `system`) has a list of OpenFGA
/// type names; the first is canonical (used for writes) and every entry is
/// consulted on reads, checks and deletes.
#[derive(Debug, Deserialize, Clone)]
pub struct OpenFGAAssignmentDriver {
    /// Base OpenFGA API url. Must end with `/` for the relative
    /// `stores/{id}/...` paths to resolve without dropping a path prefix.
    pub api_url: Url,

    /// Bearer token presented to OpenFGA. Omit for an unauthenticated store.
    #[serde(default)]
    pub api_key: Option<String>,

    /// Authorization model id. The store's latest model is used when unset.
    pub model_id: Option<String>,

    /// OpenFGA store id.
    pub store_id: String,

    /// Per-request timeout in seconds applied to the OpenFGA HTTP client.
    pub timeout: Option<u16>,

    /// How many times to retry an OpenFGA request that failed with a transient
    /// error (connection failure, timeout, HTTP 429 or 5xx). `0` (the default)
    /// disables retries. 4xx responses other than 429 are never retried.
    #[serde(default)]
    pub max_retries: u8,

    /// Base delay in milliseconds before the first retry; doubled on each
    /// subsequent attempt (exponential backoff). Ignored when `max_retries`
    /// is `0`.
    #[serde(default = "default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,

    /// Maximum number of OpenFGA requests issued concurrently when a single
    /// operation fans out over multiple actor/target representations, target
    /// kinds or role relations. `1` forces fully sequential calls. Defaults
    /// to `10`.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,

    /// Keystone role id -> OpenFGA relation name.
    pub role_to_relation: Option<HashMap<String, String>>,

    /// OpenFGA type names a Keystone user may be represented by.
    #[serde(default = "default_user_actor_types")]
    pub user_actor_types: Vec<String>,

    /// OpenFGA type names a Keystone group may be represented by.
    #[serde(default = "default_group_actor_types")]
    pub group_actor_types: Vec<String>,

    /// OpenFGA type names a Keystone project may be represented by.
    #[serde(default = "default_project_target_types")]
    pub project_target_types: Vec<String>,

    /// OpenFGA type names a Keystone domain may be represented by.
    #[serde(default = "default_domain_target_types")]
    pub domain_target_types: Vec<String>,

    /// OpenFGA type names a Keystone system scope may be represented by.
    #[serde(default = "default_system_target_types")]
    pub system_target_types: Vec<String>,

    /// Id format transform applied between Keystone and OpenFGA.
    #[serde(default)]
    pub id_transform: OpenFGAIdTransform,
}
