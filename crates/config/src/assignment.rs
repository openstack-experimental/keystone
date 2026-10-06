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

use oslo_config::ParsedSection;
use serde::{Deserialize, Deserializer};

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
///
/// The driver specific options are parsed by the type the driver crate
/// registered for its name (`oslo_config::register_block!`), so the schema
/// does not know the driver option sets.
#[derive(Debug, Clone, PartialEq)]
pub enum AssignmentBackendConfig {
    /// A `sql` backend. Carries no parameters beyond the global `[database]`;
    /// rarely needed as an explicit block (an SQL-backed domain with no
    /// mapping already shares the global instance).
    Sql,
    /// A block of another driver (e.g. `openfga`) with its own full option
    /// set, parsed with the driver's own section type.
    Named {
        /// The wire name of the driver.
        driver: String,
        /// The parsed driver configuration; downcast with
        /// [`ParsedSection::downcast_ref`].
        config: ParsedSection,
    },
}

impl AssignmentBackendConfig {
    /// The wire name of the block's driver (`"sql"` / `"openfga"`).
    pub fn driver_name(&self) -> &str {
        match self {
            Self::Sql => "sql",
            Self::Named { driver, .. } => driver,
        }
    }
}

/// Namespace under which drivers register their block types.
pub const ASSIGNMENT_BACKENDS_NAMESPACE: &str = "assignment.backends";

impl<'de> Deserialize<'de> for AssignmentBackendConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = config::Value::deserialize(deserializer)?;
        let table = value
            .clone()
            .into_table()
            .map_err(serde::de::Error::custom)?;
        let driver = table
            .get("driver")
            .ok_or_else(|| serde::de::Error::missing_field("driver"))?
            .clone()
            .into_string()
            .map_err(serde::de::Error::custom)?;
        if driver == "sql" {
            return Ok(Self::Sql);
        }
        let config = oslo_config::parse_block(ASSIGNMENT_BACKENDS_NAMESPACE, &driver, value)
            .map_err(|err| serde::de::Error::custom(format!("{err:#}")))?;
        Ok(Self::Named { driver, config })
    }
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

    #[test]
    fn sql_backend_block_parses() {
        let a = parse("[assignment.backends.local]\ndriver = sql\n");
        assert!(matches!(
            a.backend_block("local"),
            Some(AssignmentBackendConfig::Sql)
        ));
    }

    #[test]
    fn unknown_driver_block_is_rejected() {
        let err = Config::builder()
            .add_source(File::from_str(
                "[assignment.backends.x]\ndriver = nope\n",
                FileFormat::Ini,
            ))
            .build()
            .unwrap()
            .try_deserialize::<Wrapper>()
            .unwrap_err();
        assert!(format!("{err:#}").contains("nope"), "{err:#}");
    }
}
