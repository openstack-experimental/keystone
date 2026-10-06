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
//! `[openfga]` configuration of the OpenFGA assignment driver.
//!
//! The section type lives in the driver crate: the driver registers it with
//! the configuration engine, so the central schema does not know about it. The
//! same type configures both the global `[openfga]` section and a named
//! `[assignment.backends.<name>] driver = openfga` block.
use std::collections::HashMap;

use oslo_config::{ConfigSection, register_block, register_section};
use serde::Deserialize;
use url::Url;

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
#[derive(Deserialize, Clone, PartialEq)]
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

impl std::fmt::Debug for OpenFGAAssignmentDriver {
    /// Hand-written so `api_key` (a bearer token) never reaches a log line or a
    /// panic message. Its presence is still shown; its value is not.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenFGAAssignmentDriver")
            .field("api_url", &self.api_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("model_id", &self.model_id)
            .field("store_id", &self.store_id)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("retry_backoff_ms", &self.retry_backoff_ms)
            .field("max_concurrency", &self.max_concurrency)
            .field("role_to_relation", &self.role_to_relation)
            .field("user_actor_types", &self.user_actor_types)
            .field("group_actor_types", &self.group_actor_types)
            .field("project_target_types", &self.project_target_types)
            .field("domain_target_types", &self.domain_target_types)
            .field("system_target_types", &self.system_target_types)
            .field("id_transform", &self.id_transform)
            .finish()
    }
}

impl ConfigSection for OpenFGAAssignmentDriver {
    const NAME: &'static str = "openfga";
}

// The global `[openfga]` section is optional for a deployment that never
// selects the driver, so it has no `Default`: absent means "not configured".
register_section!(OpenFGAAssignmentDriver);
register_block!("assignment.backends", "openfga", OpenFGAAssignmentDriver);

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};
    use openstack_keystone_config::{AssignmentBackendConfig, AssignmentProvider};

    use super::*;

    fn parse_block(ini: &str) -> OpenFGAAssignmentDriver {
        let raw = Config::builder()
            .add_source(File::from_str(ini, FileFormat::Ini))
            .build()
            .unwrap();
        raw.get::<OpenFGAAssignmentDriver>("openfga").unwrap()
    }

    const BLOCKS: &str = r#"
[assignment]
driver = sql
domain_specific_drivers_enabled = true

[assignment.backends.central_fga]
driver = openfga
api_url = https://openfga.internal:8080/
store_id = 01ABC
max_retries = 3

[assignment.domains]
1111 = central_fga
2222 = central_fga
"#;

    /// The leaf `[assignment]` section merges with the nested
    /// `[assignment.backends.<name>]` blocks, and the block is parsed with the
    /// type this crate registered for `driver = openfga`.
    #[test]
    fn named_block_is_parsed_with_the_driver_type() {
        #[derive(Debug, Default, Deserialize)]
        struct Wrapper {
            #[serde(default)]
            assignment: AssignmentProvider,
        }
        let a = Config::builder()
            .add_source(File::from_str(BLOCKS, FileFormat::Ini))
            .build()
            .unwrap()
            .try_deserialize::<Wrapper>()
            .unwrap()
            .assignment;

        let block = a.backend_block("central_fga").expect("block present");
        assert_eq!(block.driver_name(), "openfga");
        let AssignmentBackendConfig::Named { config, .. } = block else {
            panic!("expected a named block, got {block:?}");
        };
        let cfg = config
            .downcast_ref::<OpenFGAAssignmentDriver>()
            .expect("parsed as the openfga section type");
        assert_eq!(cfg.store_id, "01ABC");
        assert_eq!(cfg.max_retries, 3);
        assert_eq!(cfg.api_url.as_str(), "https://openfga.internal:8080/");
        assert_eq!(
            a.bindable_driver_names(),
            std::collections::HashSet::from(["sql".to_string(), "openfga".to_string()])
        );
    }

    #[test]
    fn named_block_debug_redacts_the_api_key() {
        #[derive(Debug, Default, Deserialize)]
        struct Wrapper {
            #[serde(default)]
            assignment: AssignmentProvider,
        }
        let a = Config::builder()
            .add_source(File::from_str(
                "[assignment.backends.b]\ndriver = openfga\napi_url = http://fga/\nstore_id = s\napi_key = super-secret-token\n",
                FileFormat::Ini,
            ))
            .build()
            .unwrap()
            .try_deserialize::<Wrapper>()
            .unwrap()
            .assignment;
        let rendered = format!("{:?}", a.backend_block("b").unwrap());
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
    }

    /// The global `[openfga]` section reaches the driver through the engine's
    /// registry, including the environment override.
    #[tokio::test]
    async fn global_section_loads_through_the_registry() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut file,
            b"[auth]\nmethods = []\n[database]\nconnection = \"foo\"\n[openfga]\napi_url = http://fga:8080/\nstore_id = from-file\n",
        )
        .unwrap();
        let loaded = oslo_config::load_snapshot_from::<openstack_keystone_config::Config>(
            file.path().into(),
        )
        .await
        .unwrap();
        let section = loaded
            .view()
            .require::<OpenFGAAssignmentDriver>()
            .unwrap()
            .clone();
        assert_eq!(section.store_id, "from-file");
    }

    #[tokio::test]
    async fn global_section_absent_is_not_materialized() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut file,
            b"[auth]\nmethods = []\n[database]\nconnection = \"foo\"\n",
        )
        .unwrap();
        let loaded = oslo_config::load_snapshot_from::<openstack_keystone_config::Config>(
            file.path().into(),
        )
        .await
        .unwrap();
        assert!(loaded.view().section::<OpenFGAAssignmentDriver>().is_none());
    }

    #[test]
    fn defaults_apply() {
        let c = parse_block("[openfga]\napi_url = http://fga:8080/\nstore_id = s\n");
        assert_eq!(c.max_retries, 0);
        assert_eq!(c.retry_backoff_ms, 100);
        assert_eq!(c.max_concurrency, 10);
        assert_eq!(c.id_transform, OpenFGAIdTransform::None);
        assert_eq!(c.user_actor_types, vec!["user".to_string()]);
    }

    #[test]
    fn debug_redacts_the_api_key() {
        let c = parse_block(
            "[openfga]\napi_url = http://fga:8080/\nstore_id = s\napi_key = super-secret-token\n",
        );
        let rendered = format!("{c:?}");
        assert!(
            !rendered.contains("super-secret-token"),
            "api_key leaked into Debug output: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
