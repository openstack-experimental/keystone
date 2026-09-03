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

//! # Reading and caching the per-domain config files
//!
//! Pure of the service state: everything here takes a directory or a file path
//! and returns parsed [`DomainConfig`]s, so it can be exercised without a
//! running Keystone.

use std::collections::HashMap;
use std::path::Path;

use ini::Ini;
use serde_json::{Map, Value};
use tracing::warn;

use openstack_keystone_core_types::domain_config::{
    DomainConfig, DomainConfigGroupName, DomainConfigProviderError,
};

/// Every domain config file found under `domain_config_dir`, keyed by the
/// domain name its filename spells.
#[derive(Debug, Default)]
pub(crate) struct DomainConfigStore(HashMap<String, DomainConfig>);

impl DomainConfigStore {
    /// Read every `keystone.{domain_name}.conf` file in `dir`.
    ///
    /// A missing directory is not an error — it is the default deployment —
    /// and yields an empty store. A directory that cannot be read, or a file
    /// that cannot be parsed, is an error: it means the operator meant to
    /// configure something and got it wrong.
    pub(crate) fn load(dir: &Path) -> Result<Self, DomainConfigProviderError> {
        let mut store = HashMap::new();

        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    directory = %dir.display(),
                    "domain config directory does not exist; no per-domain config files loaded"
                );
                return Ok(Self(store));
            }
            Err(err) => {
                return Err(DomainConfigProviderError::Driver(format!(
                    "reading domain config directory {}: {err}",
                    dir.display()
                )));
            }
        };

        for entry in entries {
            let entry = entry.map_err(|err| {
                DomainConfigProviderError::Driver(format!(
                    "reading an entry of domain config directory {}: {err}",
                    dir.display()
                ))
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(domain_name) = domain_name_from_filename(&file_name.to_string_lossy()) else {
                warn!(
                    file = %path.display(),
                    "ignoring file not named keystone.<domain_name>.conf"
                );
                continue;
            };

            match parse_file(&path)? {
                Some(config) => {
                    store.insert(domain_name, config);
                }
                None => warn!(
                    file = %path.display(),
                    domain = %domain_name,
                    "domain config file holds no usable configuration; ignoring"
                ),
            }
        }

        Ok(Self(store))
    }

    /// The configuration stored for a domain name, if a file supplied one.
    pub(crate) fn get(&self, domain_name: &str) -> Option<&DomainConfig> {
        self.0.get(domain_name)
    }

    /// Build a store straight from parsed configurations. Test helper.
    #[cfg(test)]
    pub(crate) fn from_map(map: HashMap<String, DomainConfig>) -> Self {
        Self(map)
    }
}

/// The domain name in a `keystone.{domain_name}.conf` filename.
///
/// The name may itself contain dots (`keystone.my.domain.conf`), so only the
/// literal `keystone.` prefix and `.conf` suffix are stripped.
fn domain_name_from_filename(file_name: &str) -> Option<String> {
    let middle = file_name.strip_prefix("keystone.")?.strip_suffix(".conf")?;
    (!middle.is_empty()).then(|| middle.to_string())
}

/// Parse one domain config file into a [`DomainConfig`].
///
/// Returns `Ok(None)` when the file names no supported option at all (an empty
/// file, only unknown sections, or a section left empty once its unknown
/// options are dropped) — the same "nothing configured" the SQL driver
/// reports when a domain has no rows.
fn parse_file(path: &Path) -> Result<Option<DomainConfig>, DomainConfigProviderError> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        DomainConfigProviderError::Driver(format!("reading {}: {err}", path.display()))
    })?;
    // `noescape`: python-keystone parses these files with `configparser`, which
    // does not treat `\` as an escape. LDAP DNs are full of unescaped
    // backslashes, so honouring them here would corrupt a value that the SQL
    // driver would have stored verbatim.
    let ini = Ini::load_from_str_noescape(&text).map_err(|err| {
        DomainConfigProviderError::Driver(format!("parsing {}: {err}", path.display()))
    })?;

    let mut groups: Map<String, Value> = Map::new();
    for (section, properties) in &ini {
        let Some(section) = section else {
            warn!(
                file = %path.display(),
                "ignoring options outside any [section] in domain config file"
            );
            continue;
        };
        // Group names are lowercase, as python-keystone spells them; match
        // exactly, so a mis-cased [Ldap] is reported rather than silently honoured.
        let Ok(group) = section.parse::<DomainConfigGroupName>() else {
            warn!(
                file = %path.display(),
                section,
                "ignoring unsupported [section] in domain config file"
            );
            continue;
        };

        let options: Map<String, Value> = properties
            .iter()
            .map(|(key, value)| (key.to_string(), Value::String(value.to_string())))
            .collect();
        if options.is_empty() {
            warn!(
                file = %path.display(),
                section,
                "ignoring empty [section] in domain config file"
            );
            continue;
        }
        groups.insert(group.as_str().to_string(), Value::Object(options));
    }

    if groups.is_empty() {
        return Ok(None);
    }

    // `from_value` enforces the group shape and warn-drops options outside the
    // whitelist. What is left can still be empty (a section of only unknown
    // options); treat that as nothing configured too.
    let config = DomainConfig::from_value(Value::Object(groups))?;
    if config.is_empty() {
        Ok(None)
    } else {
        Ok(Some(config))
    }
}

#[cfg(test)]
#[path = "store/tests.rs"]
mod tests;
