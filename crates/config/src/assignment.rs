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
use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use url::Url;

use crate::common::default_sql_driver;
use crate::pagination::ListLimitConfig;

/// Assignment Provider.
#[derive(Debug, Deserialize, Clone)]
pub struct AssignmentProvider {
    /// Assignment provider driver. The global default: serves `system`
    /// targets, every unconfigured domain and every resolution fallback
    /// (ADR 0034 §4).
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// `GET /v3/role_assignments` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,

    /// Whether the assignment provider dispatches per domain (ADR 0034 §2).
    /// Off by default and independent of `[identity]
    /// domain_specific_drivers_enabled`: an operator running per-domain LDAP
    /// identity must not silently acquire per-domain assignment routing. When
    /// off, every operation goes to `driver`.
    #[serde(default)]
    pub domain_specific_drivers_enabled: bool,

    /// Named driver-configuration blocks, `[assignment.backends.<name>]`
    /// (ADR 0034 §4). Any number of domains may point at one block through
    /// `domains`; they then share a single backend instance.
    #[serde(default)]
    pub backends: HashMap<String, AssignmentBackendConfig>,

    /// `[assignment.domains]`: domain id -> backend block name (ADR 0034 §4).
    /// No per-domain parameters; the parameters live in the named block.
    #[serde(default)]
    pub domains: HashMap<String, String>,
}

impl Default for AssignmentProvider {
    fn default() -> Self {
        Self {
            driver: default_sql_driver(),
            list_limit: ListLimitConfig::default(),
            domain_specific_drivers_enabled: false,
            backends: HashMap::new(),
            domains: HashMap::new(),
        }
    }
}

impl AssignmentProvider {
    /// The set of driver names a domain's API-stored `assignment/driver`
    /// binding may name (ADR 0034 §3): `sql`, the global `driver`, and the
    /// `driver` of every `[assignment.backends.*]` block.
    pub fn bindable_driver_names(&self) -> HashSet<String> {
        let mut names = HashSet::from(["sql".to_string(), self.driver.clone()]);
        names.extend(self.backends.values().map(|b| b.driver_name().to_string()));
        names
    }

    /// The `[assignment.backends.<name>]` block, if defined.
    pub fn backend_block(&self, name: &str) -> Option<&AssignmentBackendConfig> {
        self.backends.get(name)
    }
}

/// One `[assignment.backends.<name>]` block: a `driver` discriminator plus that
/// driver's full configuration. Kept in server config, never in the API
/// (ADR 0034 §3): an API-writable driver configuration is a role-minting
/// escalation.
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "driver", rename_all = "lowercase")]
pub enum AssignmentBackendConfig {
    /// A `sql` backend. Carries no parameters beyond the global `[database]`;
    /// rarely needed as an explicit block (an SQL-backed domain with no
    /// mapping already shares the global instance).
    Sql,
    /// An `openfga` backend with its own store id, model id, API URL and
    /// bearer token. The full `[openfga]` option set is flattened at the same
    /// level as `driver = openfga`. Boxed to keep the enum small (the `Sql`
    /// variant is a unit).
    Openfga(Box<OpenFGAAssignmentDriver>),
}

impl AssignmentBackendConfig {
    /// The wire name of the block's driver (`"sql"` / `"openfga"`).
    pub fn driver_name(&self) -> &'static str {
        match self {
            Self::Sql => "sql",
            Self::Openfga(_) => "openfga",
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

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Default, Deserialize)]
    struct Wrapper {
        #[serde(default)]
        assignment: AssignmentProvider,
    }

    fn parse(ini: &str) -> AssignmentProvider {
        Config::builder()
            .add_source(File::from_str(ini, FileFormat::Ini))
            .build()
            .unwrap()
            .try_deserialize::<Wrapper>()
            .unwrap()
            .assignment
    }

    #[test]
    fn defaults_when_section_absent() {
        let a = parse("[DEFAULT]\n");
        assert_eq!(a.driver, "sql");
        assert!(!a.domain_specific_drivers_enabled);
        assert!(a.backends.is_empty());
        assert!(a.domains.is_empty());
    }

    #[test]
    fn switch_parses() {
        let a = parse("[assignment]\ndomain_specific_drivers_enabled = true\n");
        assert!(a.domain_specific_drivers_enabled);
    }

    /// Blocking check (ADR 0034 §4): the `config` INI parser must merge a leaf
    /// `[assignment]` section with the nested `[assignment.backends.<name>]`
    /// and `[assignment.domains]` sections under the same top-level name.
    #[test]
    fn leaf_and_nested_sections_merge() {
        let a = parse(
            r#"
[assignment]
driver = sql
domain_specific_drivers_enabled = true

[assignment.backends.central_fga]
driver = openfga
api_url = https://openfga.internal:8080/
store_id = 01ABC

[assignment.domains]
1111 = central_fga
2222 = central_fga
"#,
        );
        assert_eq!(a.driver, "sql");
        assert!(a.domain_specific_drivers_enabled);

        let block = a.backend_block("central_fga").expect("block present");
        match block {
            AssignmentBackendConfig::Openfga(cfg) => {
                assert_eq!(cfg.store_id, "01ABC");
                assert_eq!(cfg.api_url.as_str(), "https://openfga.internal:8080/");
            }
            other => panic!("expected openfga block, got {other:?}"),
        }

        assert_eq!(a.domains.get("1111"), Some(&"central_fga".to_string()));
        assert_eq!(a.domains.get("2222"), Some(&"central_fga".to_string()));

        assert_eq!(
            a.bindable_driver_names(),
            HashSet::from(["sql".to_string(), "openfga".to_string()])
        );
    }

    #[test]
    fn sql_backend_block_parses() {
        let a = parse("[assignment.backends.local]\ndriver = sql\n");
        assert!(matches!(
            a.backend_block("local"),
            Some(AssignmentBackendConfig::Sql)
        ));
    }
}
